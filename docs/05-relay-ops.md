# SecMPro — Relay Server: Hardening, Deployment and Operations

Status: v1 baseline (2026-09-25). Normative for `secmp-relay`, `deploy/` and the operator runbook. Research basis: `docs/research/R5-server-ops-supply-chain.md` and `R2-metadata-transport.md`.

## 1. Principles

1. **The relay must be boring.** It executes eight commands, keeps ciphertext in RAM, and forgets everything on restart. Anything else is scope creep.
2. **Can't, not won't.** Logging, persistence and identification must be technically impossible in the shipped configuration, not merely disabled.
3. **Single binary, single purpose host.** Nothing else runs on the machine except tor, the relay, sshd over WireGuard, and the base OS.
4. **Every hardening item is checked by a script** (`deploy/check-hardening.sh`, run by `cargo xtask ops-check` against a host) and the result is part of the milestone report.

## 2. Host baseline (Hetzner dedicated or cloud, Finland)

| Item | Requirement |
|---|---|
| OS | Debian 13 (kernel 6.12, systemd 257) or Ubuntu 26.04 LTS (kernel 7.0, systemd 259). Minimal install. Not Ubuntu 24.04 (systemd 255 lacks `PrivatePIDs`, `ProtectControlGroups=strict`). |
| Disk | Full-disk encryption (LUKS2) via installimage `CRYPTPASSWORD`; unlock over `dropbear-initramfs` on a WireGuard-only address or via KVM console. `/boot` unencrypted (documented evil-maid caveat). Relay keys are supplied at unlock time or stored in the encrypted root. |
| Swap | **None.** Remove swap partitions installimage created; no zram; `vm.swappiness=0` as belt-and-braces. Hibernation/hybrid-sleep masked. |
| Core dumps | `kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`, systemd-coredump `Storage=none`, `kdump` not installed. |
| Time | chrony with NTS. The relay only uses coarse hour buckets, but TLS cert validity needs correct time. |
| Kernel | `lockdown=confidentiality` if Secure Boot is available (UNVERIFIED on Hetzner — check via KVM console); otherwise `lockdown=integrity`. `kernel.yama.ptrace_scope=2`, `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `net.core.bpf_jit_harden=2`. |
| Users | No interactive users besides one admin key over WireGuard; `sudo-rs`; password login disabled. |
| SSH | `sshd` bound to the WireGuard interface only. `PermitRootLogin no`, key-only, no agent forwarding. `wtmp`/`btmp`/`lastlog` disabled (`UsePAM` with `pam_lastlog` removed, `journald` volatile). |
| Firewall | nftables: default drop inbound except WireGuard (UDP), the direct TLS port (TCP 443, optional), and Tor's outbound needs. `raw` table `notrack` for the public TCP port so conntrack holds no client state. Per-source rate limits for new connections (careful with CGNAT). Hetzner Robot firewall as a coarse outer layer (stateless, 10 rules). |
| DDoS | Hetzner's automatic protection (free). Onion service: `HiddenServiceEnableIntroDoSDefense 1` (PoW defence off in v1, ADR-024). Relay: handshake rate limit per connection/IP, frame rate limit per link, memory budget. |
| Logs | journald `Storage=volatile`, `RuntimeMaxUse=16M`, `ForwardToSyslog=no`, no rsyslog. tor: `Log notice stderr` only, `SafeLogging 1`, no `HeartbeatPeriod`. sshd `LogLevel ERROR`. |
| Memory encryption | Enable AMD SME/TSME in BIOS if exposed (`mem_encrypt=on`) — protects against cold-boot/DIMM theft only; availability on Hetzner BIOS is UNVERIFIED. |
| Updates | `unattended-upgrades` for security updates with automatic reboot window; the relay loses state on reboot by design — clients recover (spec §10.4). Announce maintenance windows to users out of band. |

## 3. Tor onion service (C tor sidecar)

`/etc/tor/torrc` essentials:

```
SocksPort 0
HiddenServiceDir /var/lib/tor/secmp/
HiddenServiceVersion 3
HiddenServicePort 443 127.0.0.1:7443
HiddenServicePoWDefensesEnabled 0     # v1: OFF — Arti clients cannot solve PoW without the experimental hs-pow-full feature (ADR-024)
HiddenServiceEnableIntroDoSDefense 1
HiddenServiceEnableIntroDoSRatePerSec 25
HiddenServiceEnableIntroDoSBurstPerSec 200
HiddenServiceNumIntroductionPoints 10
SafeLogging 1
Log notice stderr
```

Rationale for C tor over Arti for *hosting*: Arti's onion-service hosting is still documented as "testing and experimentation only" and service-side PoW is experimental (research R4 §2). Clients use Arti; the server uses C tor ≥ 0.4.9.11. Migration to Arti hosting is a v1.x item behind the `TorProvider` abstraction (which the v1.1 client work needs anyway).

**Proof-of-work defence is off in v1** (ADR-024): the PoW *client* in Arti (`hs-pow-full`) is experimental and pulls LGPL dependencies; with the relay's PoW enabled, clients would be starved exactly when the defence engages. DoS resistance in v1 rests on the intro-DoS defence above, Tor's own rate limiting, and the relay's per-connection handshake and per-link frame limits. Revisit when Arti stabilises the PoW client (OQ-16).

**No restricted discovery (client authorisation) on the relay onion**: a shared client-auth key would link all of a client's circuits at the relay. PoW is the DoS defence instead. (ADR-012)

The onion address and `relay_fp` are distributed to users out of band (they are embedded in every invitation).

## 4. Relay process (systemd)

`deploy/secmp-relay.service` (systemd ≥ 257):

```ini
[Unit]
Description=SecMPro relay (RAM-only, no logs)
After=network-online.target tor.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/secmp-relay --config /etc/secmp/relay.toml
Restart=on-failure
RestartSec=5s
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
PrivatePIDs=yes
# PrivateUsers=yes is NOT set: it strips host-namespace capabilities and breaks the port-443 bind.
# Use socket activation (secmp-relay.socket, ListenStream=443) if PrivateUsers is wanted later.
RuntimeDirectory=secmp         # optional telemetry unix socket lives here
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=strict
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
SocketBindAllow=tcp:7443
SocketBindAllow=tcp:443
SocketBindDeny=any
IPAddressDeny=any
IPAddressAllow=localhost
# When the direct TLS listener is enabled, replace the two lines above with: IPAddressAllow=any
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete @reboot @swap @module @raw-io
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitCORE=0
LimitMEMLOCK=infinity
MemoryMax=8G
TasksMax=512
LogLevelMax=notice
StandardOutput=null
StandardError=journal
LoadCredentialEncrypted=relay-keys:/etc/secmp/relay-keys.cred

[Install]
WantedBy=multi-user.target
```

Notes: `StandardOutput=null` — the relay never prints per-request data anyway; only start-up/shutdown notices go to stderr. Relay static keys are loaded from a systemd encrypted credential (TPM-bound where available). Target: `systemd-analyze security secmp-relay.service` exposure **≤ 2.0** (CI gate with `--offline`).

Inside the process (after binding sockets and loading credentials): `mlockall(MCL_CURRENT|MCL_FUTURE)`, `prctl(PR_SET_DUMPABLE, 0)`, Landlock (deny all filesystem access; UDP rules not needed since TCP only), seccomp filter tightening beyond systemd's (deny `execve`, `socket` creation after start, `ptrace`). These live in `secmp-sys-mem` and are covered by integration tests that assert e.g. `execve` fails inside the sandbox.

## 5. Relay configuration (`/etc/secmp/relay.toml`)

```toml
[listen]
tor_loopback = "127.0.0.1:7443"        # C tor forwards the onion port here (no TLS)
direct_tls   = ""                      # e.g. "0.0.0.0:443"; empty = disabled (default)

[limits]
memory_budget_bytes = 6_000_000_000    # hard cap for cells + link data
max_links_per_conn  = 1
handshakes_per_min_per_ip = 30         # direct mode only; onion mode has no IPs
frames_per_sec_per_link = 20
queue_capacity = 128                   # protocol constant; do not change without a spec change
cell_ttl_hours = 168
queue_idle_ttl_hours = 720
linkdata_ttl_hours = 720

[access]
relay_access_key_file = "/run/credentials/secmp-relay.service/relay-keys"  # contains sig/dh/kem keys + access key
relayinfo_valid_days = 45

[telemetry]
enabled = false                        # aggregate counters on a unix socket only
socket = "/run/secmp/metrics.sock"
```

Changing `queue_capacity`, `cell_ttl_hours` or frame sizes changes protocol behaviour visible to clients and MUST NOT be done without a spec/ADR change.

## 6. Operator runbook (summary; full text generated in M10)

| Task | Procedure |
|---|---|
| Generate relay keys | `secmp-relay keygen --out relay-keys.cred` (Ed25519 sig, X25519, ML-KEM-1024, access key); print `relay_fp`; encrypt as a systemd credential; back up offline (the fingerprint is what users pin — losing it means re-inviting everyone). |
| Rotate DH/KEM static keys | Monthly: `secmp-relay rotate-static` keeps `relay_sig` (fingerprint stable), issues a new `RelayInfo` with overlapping validity; clients re-fetch `RelayInfo` automatically. |
| Rotate `relay_access_key` | Distribute new key to users out of band; both keys valid for 7 days. |
| Health check | `secmp-relay ping --onion <addr>` from an operator machine over Tor: performs HELLO + handshake + `PING`; prints nothing but OK/FAIL. |
| Capacity check | Telemetry socket: total queues, total cells, memory in use, frames/s. No per-queue data exists. |
| Upgrade | Build reproducibly, verify two-builder hash match and signatures, copy binary, `systemctl restart` in the announced window. |
| Incident: host compromise suspected | Rotate all relay keys (fingerprint changes → users must update relay refs via a new invitation or a signed relay-rotation notice — v1.x feature), reinstall host from scratch, publish a notice. |
| Legal request | There is nothing to produce; the runbook contains the technical statement of what the relay stores (nothing persistent) and what it can observe (spec §11.3). |

## 7. Direct TLS listener (optional, off by default)

- rustls with the `aws-lc-rs` provider, TLS 1.3 only, key exchange groups `[X25519MLKEM768]` only, ALPN `secmp/1`, no session tickets, no 0-RTT, no client certificates.
- Certificate: self-signed Ed25519 (or ML-DSA-65 once rustls stabilises signing), long-lived, pinned by clients via `RelayRef.direct.spki_sha256`. Web PKI is not used.
- Behind the TLS stream runs the identical SecMP-LINK handshake and frames.
- The operator must understand that this listener exposes client IPs to the host and its provider; the docs mark it "testing / own-VPN use".

## 8. Capacity planning (v1)

Per queue: ≤ 128 × 4096 B ≈ 512 KiB. 10 000 queues ≈ 5 GiB worst case; typical occupancy is far lower because online recipients drain continuously. CPU: negligible (AEAD on 4 KiB frames, Ed25519 verify per command). Network: a Strict-mode contact pair at `P = 10 s` costs the relay about 10 frames (≈ 44 KB) per 10 s in each direction summed; a 1 Gbit/s uplink saturates around 25 000–28 000 concurrently active pairs, and C tor's single-threaded onion-service handling (≈ 4 rendezvous circuits per pair) will likely bind earlier — measure in M10. The unit of scale beyond that is another independent relay (architecture §5.2).

## 9. Hardening check script (M10 deliverable)

`deploy/check-hardening.sh` verifies on the host: no swap, core pattern, sysctls, journald volatile, tor options, nftables notrack rule, unit exposure score, absence of rsyslog/kdump, sshd bind address, FDE active, and that the relay binary's hash matches the signed manifest. Output is a pass/fail table; the milestone report embeds it.
