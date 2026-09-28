---
title: "R5 — Relay server, operations, supply chain and process (research brief)"
date: 2026-09-25
status: research input (not normative; the normative documents are docs/05-relay-ops.md, docs/06-engineering-standards.md and docs/08-decisions.md)
---

# SecMPro research brief: server, SRE, supply chain and process (as of 2026-09-25)

Legend: facts come from pages I fetched today (URLs in Sources). **UNVERIFIED** means I could not confirm it from a primary source. **ESTIMATE** means my own reasoning or numbers.

**Research limit:** the web-search budget ran out partway through (200/200 searches used). The remaining checks were done by fetching known primary URLs directly. A few items could not be confirmed and are marked UNVERIFIED.

## 0. Key findings
1. **Post-quantum TLS is available in Rust, but quinn does not use it by default.** rustls 0.23.45 (2026-09-14) puts X25519MLKEM768 first by default on the aws-lc-rs provider. quinn 0.11.11 enables the `rustls-ring` feature by default, and the ring provider has no ML-KEM at all. You have to switch quinn to `rustls-aws-lc-rs` explicitly.
2. **PQ certificates exist, but only for private PKI.** rustls 0.23.44 (2026-09-07) turned on ML-DSA certificates by default with aws-lc-rs. No public CA issues them, which does not matter for SecMPro because it controls both ends and can pin keys.
3. **Hetzner offers no documented SEV-SNP or TDX product.** Its AX product and docs pages say nothing about it. OVHcloud (bare metal, Feb 2026) and AWS (dedicated hosts, Jul 2026) do offer it. Attacks from 2025 (RMPocalypse, Heracles, TEE.fail) break SNP when the attacker has privileged or physical access, which a hosting provider has. **Design so that no enclave is needed.**
4. **The 1 Gbit/s NIC will limit throughput long before the CPU does** (ESTIMATE, §2). Scale by adding independent relays, SimpleX-style, not by clustering one relay.
5. **Supply-chain attacks hit Rust directly this year.** In the arrayref compromise (2026-08-20), a build-script dropper was live on crates.io for 86–107 minutes. Mini Shai-Hulud (2026-05-11) showed that valid SLSA provenance can certify malware. Countermeasures: dependency cooldown, cargo-vet, trusted publishing, and a second offline signature.
6. **Pick the OS by feature availability.** Debian 13 (kernel 6.12, systemd 257) or Ubuntu 26.04 LTS (kernel 7.0, systemd 259). Ubuntu 24.04's systemd 255 lacks PrivatePIDs, ProtectControlGroups=strict and PrivateBPF.

---

## 1. Rust async server stack

| Component | Current state (verified) |
|---|---|
| tokio | 1.53.1 (2026-07-20). LTS lines: 1.47.x until Sep 2026 (ending now); **1.51.x until Mar 2027** (MSRV 1.71). Pin with `~1.51`. |
| quinn | 0.11.11 (2026-06-22), depends on `rustls ^0.23.5`. Default features: `rustls-ring`, `ring`, `runtime-tokio`, `platform-verifier`, `bloom`, `log`. Optional: `rustls-aws-lc-rs`, `aws-lc-rs-fips`, `qlog`. |
| rustls | 0.23.45 (2026-09-14) is stable. 0.24.0-dev.1 (2026-07-23) is a pre-release (edition 2024, Rust 1.85). |
| rustls, aws-lc-rs provider | Key-exchange groups: X25519, P-256, P-384, **X25519MLKEM768**, SECP256R1MLKEM768, **MLKEM768**, **MLKEM1024** (standalone). `prefer-post-quantum` is on by default. A `fips` feature exists. |
| rustls, ring provider | X25519, P-256 and P-384 only. **No PQ.** |
| ML-DSA | Default-enabled for certificate verification with aws-lc-rs since rustls 0.23.44. rustls-webpki 0.103.14 "Support stable ML-DSA". Signing with ML-DSA keys comes through `rustls-post-quantum` (behind `aws-lc-rs-unstable`). Composite or hybrid signatures: none found (UNVERIFIED). |
| s2n-quic | 1.85.0 (2026-07-24). It uses s2n-tls/aws-lc and has an AWS blog on enabling PQ key exchange. It is a valid alternative, but it is heavier and AWS-centric. Quinn has the larger ecosystem. |

**Enabling PQ in quinn** (check the feature names against the docs at build time):
```toml
quinn  = { version = "0.11.11", default-features = false, features = ["runtime-tokio", "rustls-aws-lc-rs"] }
rustls = { version = "0.23.45", default-features = false, features = ["std", "aws_lc_rs", "prefer-post-quantum"] }
```
```rust
let mut p = rustls::crypto::aws_lc_rs::default_provider();
p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]; // own clients only: refuse classical-only
let tls = rustls::ServerConfig::builder_with_provider(Arc::new(p))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth().with_single_cert(chain, key)?;
let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
```
**Trade-off:** aws-lc-rs compiles C and assembly (AWS-LC). That complicates reproducible builds and Windows cross-compilation (clang-cl through cargo-xwin). It is still the only rustls provider with ML-KEM, and libcrux is not a rustls provider.

**How comparable servers deliver messages:**
- **SimpleX SMP:**
  - Each queue has three unlinkable IDs (recipient, sender, notifier).
  - Transport blocks are a fixed 16,384 bytes; the maximum message is 16,048 bytes.
  - A full queue returns `ERR QUOTA` until the recipient drains *all* messages.
  - Messages are deleted on `ACK` or after a TTL. The spec says servers must not keep command logs or database snapshots.
  - SimpleX does persist, though: the store log has been on by default since v6.3.2, journal message storage arrived in v6.3.1 (beta), and a PostgreSQL message store in v6.5.0.
- **Signal-Server:** messages go to a Redis cache first (routed to WebSocket connections via pub/sub), then a background persister moves them to DynamoDB with a TTL. A 2023-era analysis reports 7 days; the current value is UNVERIFIED.

**Memory-only queue design (recommended for v1):**
- **Sharding:** a sharded map `QueueId → Queue`, with 4× as many shards as cores. Use a `parking_lot::Mutex` per shard or one actor per shard; never a global lock.
- **Queues:** each queue is a bounded `VecDeque` of fixed-size padded blobs, with a cap on both message count and bytes. Each entry stores an absolute expiry time. Expire lazily when a queue is accessed, plus a periodic sweep per shard (timing wheel).
- **Global memory budget:** an atomic byte counter. When it crosses its limit, refuse *new queues* first, then new messages, with an explicit error. Never block tokio worker threads.
- **Backpressure chain:**
  - Transport level: QUIC flow control via quinn `TransportConfig` (`receive_window`, `stream_receive_window`, `max_concurrent_bidi_streams`).
  - Per connection: bounded `mpsc` command pipelines.
  - Application level: a queue-full error (like `ERR QUOTA`) and client retry with jittered backoff.
- **Secret hygiene:** zeroize buffers on ACK or expiry, because the allocator does not scrub freed memory.

**Is restart-safe storage worth it?** Messages are already end-to-end encrypted, so an at-rest spool, even one "encrypted with client-derived keys", mainly adds *metadata on disk*: which queues exist, pending counts, timestamps. Two options:
- A key that allows an unattended reboot is a key someone who seizes the server can also use.
- A RAM-only key loses the spool on a crash, which defeats its purpose.

**Recommendation for v1:** no persistence. Clients keep an outbox and resend until an end-to-end delivery receipt arrives. Add a graceful-drain phase on SIGTERM (stop accepting sends, let recipients fetch for N seconds). Revisit "socket and state handoff to the new process" (memfd plus SCM_RIGHTS) only if restart loss hurts in practice.

**Recommendations for SecMPro:**
- quinn + rustls/aws-lc-rs.
- TLS 1.3 only; X25519MLKEM768 only for your own clients.
- Pin the server key or certificate in the queue address (the SimpleX fingerprint model) instead of using WebPKI.
- Transport authentication can stay Ed25519 for v1 (it only needs to hold at connection time). Plan ML-DSA-65 pinned certificates for v1.x.
- Disable TLS session tickets, resumption and 0-RTT: they link sessions over time.
- Build the protocol logic as a **sans-IO state machine**, like quinn-proto, so it can be tested and verified without a network (§6).

## 2. Scalability

- **Unit of scale = an independent relay.** Queue addresses carry the server host and key fingerprint. Clients create each contact's queues on different servers and rotate them. Adding a server needs no shared state and creates no cross-server linkability, because relays never talk to each other. SimpleX's 2-hop private routing (v5.8) adds a relay the sender chooses in front of the recipient's relay, so the destination relay never sees the sender's IP address.
- **Within one relay:** thread-per-core or tokio multi-thread, with shards keyed by queue ID.
- **One logical relay across several hosts (only if needed):**
  - The shard ID can live inside the queue ID, which reveals nothing beyond which server holds it.
  - QUIC routing: quinn `EndpointConfig` accepts a custom `ConnectionIdGenerator` ("embed information in local connection IDs … stateless packet-level load balancers").
  - The IETF QUIC-LB draft (-21) **expired Feb 2026** without becoming an RFC. Prefer DNS or IP-per-shard over a CID-routing load balancer.
  - If a load balancer is used, route by rendezvous (HRW) hashing on queue ID.
- **Throughput (ESTIMATE, to be measured):**
  - A 16 KiB padded message is about 12 QUIC packets.
  - Tuned QUIC stacks run roughly 1–3 Gbit/s per core. Fastly measured optimized QUIC at TCP+TLS parity; a KIT 2025 study found senders single-core-bound.
  - That gives about 4–12k relayed 16 KiB messages per second per core. With 2–4 KiB padding buckets, roughly 3–5× more.
  - **Network ceiling:** 1 Gbit/s full duplex carries about 7k messages/s of 16 KiB. An EPYC 9454P (48 cores) will saturate a 10 Gbit uplink long before its CPU. Size by NIC and RAM: 1M queues × 2 pending × 16 KiB ≈ 32 GiB.
- **Recommendations for SecMPro:**
  - Choose padding buckets early (fewer sizes is better for privacy).
  - Benchmark early with a load generator of 2 clients plus the server.
  - Plan "more relays, operated independently", not a cluster.

## 3. Confidential computing on Hetzner

- **No Hetzner offering found.** AX pages (AX41, AX42, AX102, AX162 with EPYC 9454P) and AX add-on docs do not mention SEV, SME, TDX or TPM. The KVM console is free for 3 hours on request, but the docs do not say whether BIOS options such as SNP, SMEE or RMP are exposed: **UNVERIFIED, ask support**. Hetzner Cloud has no documented CVM product.
- **Tooling is mature:**
  - Linux 6.11 and QEMU 9.1 added SNP host support upstream.
  - Ubuntu 26.04 includes TDX host support and SNP in its virtualization stack.
  - Crates: `sev` 8.0.0 (2026-05-27) and `snpguest` 0.10.0 (2025-11-13), which covers reports, VCEK/ASK/ARK chains from AMD KDS, verification and key derivation.
- **Threat fit is poor for this hosting model:**
  - RMPocalypse (CCS 2025, Zen 3–5): one 8-byte write breaks the RMP and allows forged attestation.
  - Heracles (CCS 2025): a chosen-plaintext attack on SNP.
  - TEE.fail (IEEE S&P '26): a DDR5 interposer for under $1,000 breaks SNP, TDX and SGX and forges attestation. There is no firmware fix.
  - The adversary SecMPro worries about (hoster or state, with physical access) is exactly the one in scope for these attacks.
- **SME/TSME:** host memory encryption against cold-boot and DIMM theft. It needs a BIOS setting plus `mem_encrypt=on`; check with `dmesg | grep -i "memory encryption"`. It does not protect against root. Availability on Hetzner BIOSes is UNVERIFIED.
- **Recommendation for SecMPro:**
  - Do **not** depend on an enclave.
  - Avoid needing private contact discovery by having no global user identifiers: invite links and QR codes, as SimpleX does.
  - Treat SNP as optional defence-in-depth for v2+, on providers that document it.

## 4. Linux hardening for the relay

**systemd unit** (systemd 257 or newer = Debian 13; 259 = Ubuntu 26.04):
```ini
[Service]
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
PrivatePIDs=yes                # v257+
PrivateUsers=yes
PrivateBPF=yes                 # v258+ (not Debian 13)
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=strict    # values private|strict since v257
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
KeyringMode=private
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SocketBindAllow=udp:443
SocketBindDeny=any
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE   # or use socket activation / unprivileged_port_start and drop all
LimitCORE=0
LimitMEMLOCK=infinity
MemoryMax=...
TasksMax=...
LogLevelMax=notice
```
Notes on the unit:
- `IPAddressDeny=any` fits outbound-only helpers, not a public relay. For the relay, use `SocketBindAllow`/`SocketBindDeny` as above.
- Put `systemd-analyze security --offline=yes --threshold=<n>` in CI. **Aim for exposure ≤ 2.0** (my target; the man page, systemd 262~devel, does not publish label cut-offs).
- systemd 262 was released 2026-09-22.

**Inside the process (after binding sockets):**
- Landlock:
  - `landlock` crate 0.4.7 (2026-07-27), ABI V1–V9.
  - ABI to kernel mapping: V6 = 6.12 (signal and abstract-UNIX scoping), V7 = 6.15 (audit), V8 = 7.0, V9 = 7.1.
  - **UDP rules arrive only in ABI 10** (current mainline docs). On Debian 13 and Ubuntu 26.04, Landlock cannot restrict QUIC sockets; use it for filesystem denial plus scoping.
- seccomp: `seccompiler` 0.5.0 (2025-03-07). Install a tighter filter after init that denies `execve`, `socket`, `bind`, `ptrace` and filesystem writes.
- Memory: `mlockall(MCL_CURRENT|MCL_FUTURE)` and `prctl(PR_SET_DUMPABLE,0)`. Put these in a tiny audited `sys` crate; everything else uses `forbid(unsafe_code)`.
- Host settings: no swap and no zram (Hetzner installimage layouts often include swap, so remove it), mask `hibernate`/`hybrid-sleep`, no kdump, `kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`, systemd-coredump `Storage=none`.
- Kernel: `lockdown=confidentiality`. Whether Hetzner exposes UEFI Secure Boot is UNVERIFIED.

**Logging:**
- journald `Storage=volatile` with a small `RuntimeMaxUse=`, or `Storage=none` (drops everything), plus `ForwardToSyslog=no` and no rsyslog.
- The application logs only aggregate counters: no queue IDs, IP addresses or per-queue metrics labels.

**Disk encryption:**
- Hetzner community tutorial (2026-02-01): installimage with `CRYPTPASSWORD`, an unencrypted `/boot`, `dropbear-initramfs` on port 2222 and `cryptroot-unlock`. Its caveat is evil-maid tampering of `/boot`.
- Clevis/Tang (a Tang server at another provider) allows unattended reboot. It is the weaker option: whoever reaches Tang can decrypt.
- With RAM-only queues, full-disk encryption mainly protects the server identity keys. Consider supplying those at unlock time.

**What still leaks on a "no logs" server:**
- The `nf_conntrack` table holds client IP and port per UDP flow. Use an nftables `raw` table with `notrack` for udp/443, which also removes a DoS state-exhaustion target.
- sshd, wtmp and btmp. Remove public SSH; manage over WireGuard or vSwitch only.
- The QUIC connection table, and Retry/NEW_TOKEN tokens that encode the client address. Rotate the in-memory token key and keep short lifetimes.
- TLS resumption tickets.
- Allocator residue.
- Provider-side flow and DDoS telemetry, which the server cannot control. Answer that on the client side: 2-hop routing, Tor.

**DDoS:**
- Hetzner's automatic DDoS protection is included at no cost.
- The Robot firewall is **stateless, 10 rules per direction**, and cannot filter IPv6 by address.
- nftables per-source meters (`limit rate over … per ip saddr`), with care for users behind CGNAT.
- quinn `Incoming::retry()` when `!remote_address_validated()` under load, plus handshake-rate caps.
- Optional anonymous rate-limit tokens or PoW for queue creation.
- Tor onion services have Equi-X PoW on by default in C tor ≥ 0.4.8 (`HiddenServicePoWDefensesEnabled`, `…QueueRate`, `…QueueBurst`). **Onion services carry TCP only**, so an onion endpoint needs a TCP+TLS transport variant, not QUIC.

**OS choice:**

| OS | Kernel / Landlock | systemd | Notes |
|---|---|---|---|
| Ubuntu 24.04 | 6.8 GA (ABI 4), HWE 6.17 | 255 | Lacks PrivatePIDs and cgroup strict. |
| Debian 13.7 (2026-09-12) | 6.12.107 (ABI 6) | 257 | Conservative; good default. |
| Ubuntu 26.04 LTS (2026-04-24) | 7.0 (ABI 8) | 259 | sudo-rs, chrony with NTS by default, SNP/TDX host; support until 2031. |

Talos is Kubernetes-only, so it does not fit.

**Recommendations for SecMPro:**
- Debian 13 or Ubuntu 26.04 minimal for v1.
- Move to an image-based build later: mkosi or bootc, UKI plus dm-verity with a read-only root. Installing these through Hetzner's rescue system is UNVERIFIED.

## 5. Supply chain and build integrity

**Tools (latest versions):** cargo-audit 0.22.2 (2026-06-05), cargo-deny 0.20.2 (2026-07-09), cargo-vet 0.10.2 (2026-01-13), cargo-crev 0.27.1 (2026-04-12), cargo-auditable 0.7.6 (2026-09-13), cargo-cyclonedx 0.5.9 (2026-03-19).

**cargo-vet audit imports** (registry): Google, Mozilla, Bytecode Alliance, ISRG, Zcash, Embark, Fermyon, Actix, Ariel OS.

**Incidents to design against:**
- **Rust, 2026-08-20:** a compromised maintainer account republished arrayref 0.3.10, internment 0.8.7 and append-only-vec 0.1.9. Each depended on `proc-macro1`, whose `build.rs` downloaded an infostealer (browser credentials, persistence). The versions were live 86–107 minutes; arrayref has 245M all-time downloads.
- **Rust typosquats:** Dec 2025 (`finch_cli_rust`, `sha-rst`) and Feb 2026 (`polymarket-client-sdks`).
- **npm:**
  - Shai-Hulud (Sep 2025) and 2.0 (Nov 2025).
  - Mini Shai-Hulud (2026-05-11): TanStack's `pull_request_target` workflow, then pnpm cache poisoning, then an OIDC token scraped from runner memory. The result was npm and PyPI packages **with valid SLSA provenance and Sigstore signatures**.
  - Shai-Hulud/ChainDrop (Aug 2026): keyv, over 1,300 versions.

**Registry and cargo controls:**
- crates.io Trusted Publishing: GitHub (Jul 2025), then GitLab, plus an **enforce-TP-only** mode. It blocks `pull_request_target` and `workflow_run` triggers (Jan 2026 update).
- Cargo **`min-publish-age`**: stabilization PR #17335 was in FCP (2026-08-18). A tracking issue says it ships in **Rust 1.100 on 2026-11-12**:
  ```toml
  [registry]
  global-min-publish-age = "7 days"
  ```
  Until then, use a Renovate or Dependabot cooldown. Current stable is therefore about Rust 1.98 (derived from that schedule).

**SLSA and signing:**
- SLSA **v1.2 final was released 2025-11-24** and adds a Source track.
- For Build L3: GitHub artifact attestations from a *reusable workflow*, verified with `gh attestation verify --signer-workflow …`. OSPS Baseline is at v2026.08.28.

**Reproducible builds:**
- What breaks them: absolute paths from `$CARGO_HOME` and the workspace, build.rs or proc-macro nondeterminism, C dependencies (aws-lc-sys, cc/cmake versions), linker or toolchain drift, differing `RUSTFLAGS` (which change `-C metadata`), and timestamps (`SOURCE_DATE_EPOCH`).
- Fixes:
  - `--remap-path-prefix` for now. `profile.trim-paths` stabilization PR #17488 was opened 2026-09-18, targeting 1.101, with no default for release profiles.
  - An exact `rust-toolchain.toml` pin.
  - `--locked --frozen` with `cargo vendor`.
  - A pinned container digest, or Nix (crane) / Guix.
  - Compare hashes from two independent builders and investigate differences with `diffoscope`.
- rustup does not verify signatures on downloads.

**Recommendations for SecMPro:**
1. **Dependency policy:** an allowlist in `deny.toml` (`[bans]`, sources limited to crates.io, no git dependencies unless pinned by `rev`); cargo-vet with the imports above; and a human-approved ADR for any new crate. This also blocks LLM-hallucinated crate names ("slopsquatting").
2. **Builds:** 7-day cooldown; `cargo auditable` builds; a CycloneDX SBOM per release.
3. **CI hygiene:** no `pull_request_target`; actions pinned by SHA; no shared caches between untrusted and release workflows; enforce-TP-only if you publish crates.
4. **Dual signing:** CI provenance (Build L3) **plus** an offline maintainer signature (minisign or ssh-sig) added *after* an independent reproducible rebuild matches. This directly addresses the Mini Shai-Hulud failure mode.
5. **Code rules:** `#![forbid(unsafe_code)]` everywhere except one tiny `sys` crate; MSRV = the pinned toolchain.

## 6. Testing and CI

**Tools:** cargo-nextest 0.9.145 (2026-09-16), cargo-mutants 27.1.0 (2026-06-02), cargo-llvm-cov (version not checked), turmoil 0.7.2 (2026-04-24: TCP and UDP simulation, partitions, hold/release, seeded, tokio-native), madsim 0.2.34 (2025-10-11, less active), Kani 0.68.0 (2026-09-16: function contracts; checks overflow and panics).

**Crypto test vectors (KATs):**
- **Wycheproof** (now C2SP): `testvectors_v1` JSON covering X25519, EdDSA, ChaCha20/XChaCha20-Poly1305, AES-GCM, HKDF, ML-KEM, ML-DSA.
- RFC vectors: 7748, 8032, 8439, 5869, 9180.
- NIST ACVP vectors for FIPS 203 and 204.
- Consider **libcrux-ml-kem** 0.0.10 (2026-07-15), formally verified with hax/F*, if not using AWS-LC.

**Recommendations for SecMPro:**
1. **Test layers:**
   - Sans-IO core with property tests (proptest) and Kani harnesses on parsers and queue/ratchet state machines.
   - cargo-fuzz on every decoder, with a short smoke run on each PR and long runs nightly.
   - An in-process interop harness: server plus 2 clients on tokio.
   - turmoil for loss, partition and latency. Running quinn on top of turmoil UDP needs a custom `AsyncUdpSocket` (UNVERIFIED effort); otherwise inject faults at the sans-IO boundary.
   - Miri on the `sys` crate and on core crates.
   - Mutation testing: **no surviving mutants in the protocol and crypto crates**, or each one explained in a note.
2. **Windows:**
   - `cargo-xwin` 0.23.1 (2026-08-13) builds `x86_64-pc-windows-msvc` from Linux. It downloads the MSVC CRT and SDK (you must accept Microsoft's licence), can cache them offline, and uses clang-cl for C dependencies such as aws-lc-sys.
   - Prefer `-msvc` over `-gnu`, which is a different CRT/ABI and less common for shipping.
   - Run tests and signed release builds on the owner's libvirt Windows 11 VM as a runner that is **ephemeral** (revert to a snapshot per job), holds no secrets, and **never runs fork PRs**.

## 7. Audits and disclosure

**Who audits projects like this:**
- Trail of Bits audited SimpleX twice: 2022 implementation, and a July 2024 crypto design review (3 medium, 1 low, 3 informational findings).
- Cure53, NCC and Radically Open Security (ROS, non-profit) are the usual firms.
- OSTIF brokers audits; its 2026 audits were mostly cloud and AI projects.

**Who can pay for it:**
- **OTF Security Lab** is accepting applications. It covers audits and architecture reviews through partners including ROS, 7ASecurity, Include Security, SRLabs, Atredis and Subgraph.
- **Sovereign Tech Resilience** (Germany) offers code audits and a bug-bounty platform.
- **NLnet NGI0 Commons Fund: the final (13th) call closed 2026-06-01.** Its services included ROS audits and NixOS packaging. A successor programme is UNVERIFIED.

**Disclosure:**
- `SECURITY.md` plus GitHub private vulnerability reporting.
- `/.well-known/security.txt` (RFC 9116, 2022): `Contact` and `Expires` are required; `Encryption`, `Policy`, `Canonical`, `Preferred-Languages`, `Acknowledgments` and `Hiring` are optional. Sign it with OpenPGP.

**Threat modelling:**
- OWASP / Threat Modeling Manifesto 4 questions, STRIDE per data-flow-diagram element.
- LINDDUN for privacy: GO cards, PRO, and the new **MAESTRO** method (Springer SoSyM, 2025-11-26), which adds six architectural viewpoints.
- Model the "can / cannot learn" tables per adversary on SimpleX's `overview-tjr.md`.

**Recommendation for SecMPro, in this order:**
1. Spec, threat model and ProVerif/Tamarin model.
2. Crypto design review (apply to OTF or STA).
3. Implementation audit before public v1.
4. Publish the reports.

## 8. Repository and the AI-driven build process

**Layout:**
```
secmpro/  Cargo.toml ([workspace.dependencies], [workspace.lints])  rust-toolchain.toml  deny.toml  supply-chain/
  crates/proto        # wire format, sans-IO, no crypto impl
  crates/crypto       # ONLY crate allowed to import crypto crates; thin wrappers, typed keys/nonces
  crates/server  crates/client-core  crates/sys (only unsafe)  crates/testkit (harness, KAT loaders)
  fuzz/  xtask/ (repro-check, release, sbom)  vectors/  docs/{spec,threat-model,adr}
```
- ADRs: MADR 4.0.0 in `docs/decisions/NNNN-*.md`, including its "Confirmation" section.
- Conventional Commits 1.0.0 (`feat!:` or a `BREAKING CHANGE:` footer).

**Lints:**
- `unsafe_code = "forbid"`.
- Clippy `pedantic` as warnings, plus deny for: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `dbg_macro`, `print_stdout`, `todo`, `mem_forget`.
- `clippy.toml` `disallowed-methods` / `disallowed-types`: ban non-OS RNGs, `==` helpers on secret types, and `Debug` on key types.

**Pitfalls when an LLM writes crypto, and the guard for each:**

| Pitfall | Guard |
|---|---|
| Invented constructions (custom KDF/MAC/XOR schemes) | Primitives come from an allowlist; each construction needs a spec and an ADR. |
| Nonce reuse (counter reset on restart, same nonce in both directions, random 96-bit nonces with long-lived keys) | XChaCha20 or per-message keys; `Nonce` newtypes that are not `Clone`. |
| Non-constant-time comparisons, secret-dependent branches | `subtle::ConstantTimeEq`; secret types without `PartialEq`. |
| Missing domain separation, AAD or transcript binding | Review checklist item. |
| Unchecked inputs (low-order X25519 points / all-zero shared secret, non-strict Ed25519, ML-KEM encapsulation-key checks, implicit rejection) | Wycheproof negative vectors. |
| Secrets in logs or `Debug`, missing `zeroize` | `secrecy` + `zeroize` crates; redacted `Debug`. |
| Tests that only round-trip against their own code | External test vectors are mandatory; mutation testing. |
| Error or timing oracles; panics on malformed input | Fuzzing, the overflow lints, Kani proofs on parsers. |
| Hallucinated crate names | Allowlist, cargo-vet, cooldown. |

**Definition of done per milestone:**
- All of the following pass: fmt, clippy with the deny set, nextest, doctests, Miri subset, deny/audit/vet, fuzz smoke, all test vectors, mutation gate, coverage ≥ 90% on proto and crypto.
- Reproducible-build hash matches on 2 builders; SBOM generated; provenance and offline signature on artifacts.
- Server unit scores ≤ threshold in `systemd-analyze security`.
- Threat-model changes and ADRs updated; the Fable review checklist is signed off; any crypto change gets two reviewers.

## Open questions and uncertainties
- Whether Hetzner AX162 (EPYC) BIOS exposes SEV-SNP, SME or TSME and Secure Boot through the KVM console: **UNVERIFIED, ask support**.
- Signal's current message TTL (the 7-day figure is from an older analysis): UNVERIFIED.
- Exact rustls feature names for `default-features=false` builds, and the maturity of ML-DSA *signing* (the `aws-lc-rs-unstable` flag): check at build time.
- Running quinn over turmoil UDP, and the Landlock ABI 10 kernel version: UNVERIFIED.
- Current stable Rust ≈ 1.98 is derived from the 1.100 date, not read directly. Whether `min-publish-age` actually lands in 1.100 depends on the FCP outcome.
- Throughput numbers are ESTIMATES; benchmark on the target hardware.
- A successor funding call to NGI0 Commons: UNVERIFIED.

## Sources
- rustls docs: https://docs.rs/rustls/latest/rustls/
- rustls ring key-exchange groups: https://docs.rs/rustls/latest/rustls/crypto/ring/kx_group/index.html
- rustls aws-lc-rs key-exchange groups: https://docs.rs/rustls/latest/rustls/crypto/aws_lc_rs/kx_group/index.html
- rustls versions (crates.io API): https://crates.io/api/v1/crates/rustls
- rustls releases: https://github.com/rustls/rustls/releases
- Phoronix, rustls 0.23.44: https://www.phoronix.com/news/Rustls-0.23.44-Released
- Hardware Busters, ML-DSA default: https://hwbusters.com/news/rustls-turns-on-post-quantum-ml-dsa-certificates-by-default-and-the-web-pki-still-cant-use-them/
- rustls-webpki 0.103.14: https://github.com/rustls/webpki/releases/tag/v/0.103.14
- rustls-post-quantum: https://docs.rs/rustls-post-quantum/latest/rustls_post_quantum/
- quinn crate page: https://docs.rs/crate/quinn/latest
- quinn feature flags: https://docs.rs/crate/quinn/latest/features
- quinn `Incoming`: https://docs.rs/quinn/latest/quinn/struct.Incoming.html
- quinn `EndpointConfig`: https://docs.rs/quinn/latest/quinn/struct.EndpointConfig.html
- tokio: https://docs.rs/crate/tokio/latest
- s2n-quic: https://crates.io/api/v1/crates/s2n-quic
- AWS blog, PQ in s2n-quic: https://aws.amazon.com/blogs/security/enable-post-quantum-key-exchange-in-quic-with-the-s2n-quic-library/
- SMP protocol spec: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- simplexmq changelog: https://github.com/simplex-chat/simplexmq/blob/master/CHANGELOG.md
- SimpleX threat model: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md
- SimpleX v5.8 private routing: https://simplex.chat/blog/20240604-simplex-chat-v5.8-private-message-routing-chat-themes.html
- SimpleX v6.1 security review: https://simplex.chat/blog/20241014-simplex-network-v6-1-security-review-better-calls-user-experience.html
- Signal-Server analysis (SoftwareMill): https://softwaremill.com/what-ive-learned-from-signal-server-source-code/
- QUIC-LB draft: https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/
- Fastly, QUIC vs TCP efficiency: https://www.fastly.com/blog/measuring-quic-vs-tcp-computational-efficiency
- KIT 2025 QUIC throughput study: https://doc.tm.kit.edu/2025-Examining-the-Heterogeneous-Throughput-Performance-Landscape-of-QUIC-Implementations-Koenig-et-al.pdf
- Hetzner AX matrix: https://www.hetzner.com/dedicated-rootserver/matrix-ax/
- Hetzner AX add-ons: https://docs.hetzner.com/robot/dedicated-server/server-lines/ax-server/
- Hetzner KVM console: https://docs.hetzner.com/robot/dedicated-server/maintainance/kvm-console/
- Hetzner Robot firewall: https://docs.hetzner.com/robot/dedicated-server/firewall/
- Hetzner DDoS protection: https://www.hetzner.com/unternehmen/ddos-schutz/
- Hetzner Ubuntu 24.04 FDE tutorial: https://community.hetzner.com/tutorials/install-ubuntu-2404-with-full-disk-encryption/
- AWS SEV-SNP dedicated hosts: https://aws.amazon.com/about-aws/whats-new/2026/07/ec2-amd-sev-snp-dedicated-hosts/
- OVHcloud bare-metal SEV-SNP (bex.co): https://bex.co/blog/2026/07/31/ovhcloud-sev-snp-confidential-computing-bare-metal
- sev crate: https://crates.io/api/v1/crates/sev
- snpguest crate: https://crates.io/api/v1/crates/snpguest
- virtee/sev: https://github.com/virtee/sev
- Linux 6.11 SNP (Phoronix): https://www.phoronix.com/news/Linux-611-AMD-SEV-SNP-KVM-Guest
- RMPocalypse: https://rmpocalypse.github.io/
- Heracles: https://heracles-attack.github.io/Heracles-CCS2025.pdf
- TEE.fail: https://tee.fail/
- systemd 257 (LWN): https://lwn.net/Articles/1001657/
- systemd v258 NEWS: https://raw.githubusercontent.com/systemd/systemd/v258/NEWS
- systemd v258 highlights (LWN): https://lwn.net/Articles/1039481/
- systemd 262 release: https://www.linuxcompatible.org/story/systemd-262-release-hardwarerooted-security-and-live-updates
- systemd-analyze man page: https://man7.org/linux/man-pages/man1/systemd-analyze.1.html
- journald.conf man page: https://man7.org/linux/man-pages/man5/journald.conf.5.html
- Landlock kernel docs: https://docs.kernel.org/userspace-api/landlock.html
- landlock crate ABI enum: https://landlock.io/rust-landlock/landlock/enum.ABI.html
- rust-landlock changelog: https://github.com/landlock-lsm/rust-landlock/blob/main/CHANGELOG.md
- Landlock news #5: https://landlock.io/news/5/
- landlock crate: https://crates.io/api/v1/crates/landlock
- seccompiler crate: https://crates.io/api/v1/crates/seccompiler
- Ubuntu 26.04 release (CNX): https://www.cnx-software.com/2026/04/24/ubuntu-26-04-lts-resolute-raccoon-released-with-linux-7-0/
- Ubuntu 26.04 summary for LTS users: https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/
- Debian 13.7: https://www.debian.org/News/2026/20260912
- Tor onion service DoS guide: https://community.torproject.org/onion-services/advanced/dos/
- Tor PoW spec: https://spec.torproject.org/hspow-spec/index.html
- Rust blog, arrayref attack: https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
- The Hacker News, arrayref: https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
- crates.io malicious-crate policy: https://blog.rust-lang.org/2026/02/13/crates.io-malicious-crate-update
- crates.io Jan 2026 update: https://blog.rust-lang.org/2026/01/21/crates-io-development-update
- crates.io Jul 2025 update: https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07
- cargo PR #17335 (min-publish-age): https://github.com/rust-lang/cargo/pull/17335
- cooldowns tracking issue: https://github.com/mprpic/cooldowns/issues/30
- cargo PR #17488 (trim-paths): https://github.com/rust-lang/cargo/pull/17488
- Reproducible Builds, Rust: https://reproducible-builds.org/docs/rust/
- Rust supply-chain security guide: https://rust-secure-code.github.io/rust-supply-chain-security/build.html
- SLSA blog: https://slsa.dev/blog
- SLSA, Mini Shai-Hulud: https://slsa.dev/blog/2026/05/mini-shai-hulud-what-slsa-can-and-cannot-do
- GitHub SLSA Build L3 guide: https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3
- CSA Singapore Shai-Hulud advisory: https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/
- Microsoft, Shai-Hulud 2.0: https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/
- OSPS Baseline: https://baseline.openssf.org/
- cargo-vet registry: https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml
- Tool versions (crates.io API):
  - https://crates.io/api/v1/crates/cargo-vet
  - https://crates.io/api/v1/crates/cargo-deny
  - https://crates.io/api/v1/crates/cargo-audit
  - https://crates.io/api/v1/crates/cargo-crev
  - https://crates.io/api/v1/crates/cargo-auditable
  - https://crates.io/api/v1/crates/cargo-cyclonedx
  - https://crates.io/api/v1/crates/cargo-nextest
  - https://crates.io/api/v1/crates/cargo-mutants
  - https://crates.io/api/v1/crates/turmoil
  - https://crates.io/api/v1/crates/madsim
  - https://crates.io/api/v1/crates/cargo-xwin
  - https://crates.io/api/v1/crates/kani-verifier
  - https://crates.io/api/v1/crates/libcrux-ml-kem
- turmoil docs: https://docs.rs/turmoil/latest/turmoil/
- cargo-xwin: https://github.com/rust-cross/cargo-xwin
- Kani: https://github.com/model-checking/kani
- Cryspen, ML-KEM verification: https://cryspen.com/post/ml-kem-verification/
- Wycheproof (C2SP): https://github.com/C2SP/wycheproof
- RFC 9116: https://www.rfc-editor.org/rfc/rfc9116.html
- OWASP threat modeling cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- LINDDUN MAESTRO: https://link.springer.com/article/10.1007/s10270-025-01342-w
- NLnet Commons Fund: https://nlnet.nl/commonsfund/
- NLnet NGI0 services: https://nlnet.nl/NGI0/services/
- Sovereign Tech Agency programs: https://www.sovereign.tech/programs
- OTF Security Lab: https://www.opentech.fund/labs/security-lab/
- OSTIF audits: https://ostif.org/category/audits/
- MADR: https://adr.github.io/madr/
- Conventional Commits: https://www.conventionalcommits.org/en/v1.0.0/
