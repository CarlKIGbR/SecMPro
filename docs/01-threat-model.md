# SecMPro — Threat Model

Status: v1 baseline (2026-09-25). This document is the reference for every "is this acceptable?" question during implementation and review. When code and this document disagree, the code is wrong or this document must be changed through an ADR.

Method: assets → adversaries → per-adversary "can / cannot learn or do" tables (SimpleX `overview-tjr.md` style) → STRIDE per trust boundary → LINDDUN privacy threats → residual risks. The screen-capture threat is treated in its own section because the requirement ("immune to screenshot attacks") needs precise wording.

## 1. Assets

| Asset | Where it lives | Compromise means |
|---|---|---|
| A1 Message content | Client memory/store only, cells in transit (E2E) | Confidentiality loss |
| A2 Social graph (who talks to whom) | Client store only | Deanonymisation, coercion |
| A3 Activity pattern (when/how much someone communicates) | Derivable from network traffic unless hidden | Surveillance |
| A4 Identity key sets (IKS) and session state | Client store (wrapped), client memory | Impersonation, decryption of future traffic (PCS limits past) |
| A5 Network location (IP) of users | Only the Tor guard sees it; relay never | Deanonymisation |
| A6 Invitations (unconsumed) | Out-of-band channel, client store | Contact hijacking |
| A7 Relay static keys | Relay host | Enables active MITM of *links* (not of E2E), not decryption of past links (FS) |
| A8 Displayed content on screen | Client UI | Screenshot exfiltration |
| A9 Build artefacts / dependencies | CI, registries | Backdoored client or relay |

## 2. Adversaries

| Id | Adversary | Capabilities assumed |
|---|---|---|
| ADV-R | **Relay operator / compromised relay** | Full control of the relay process and host: read RAM, modify code, drop/delay/reorder/replay cells, correlate timing, keep logs, collude with ADV-N. |
| ADV-N | **Network observer** (local network, ISP, hosting provider, Tor entry guard or exit-side observer, global passive adversary) | Sees packet sizes and timing on links it observes; may inject/drop. Global passive adversary assumed only for stating limits. |
| ADV-C | **Malicious contact** | A legitimate session partner who tries to learn more than the content sent to them, spam, replay, or impersonate. |
| ADV-I | **Invitation thief** | Obtains an unconsumed invitation (shoulder-surfing a QR, intercepting the out-of-band channel). |
| ADV-T | **Device thief (offline)** | Physical access to a powered-off or locked device; can image the disk. |
| ADV-M | **Same-user malware** | Code running as the user on the client machine, without admin/root. Can read the user's files, inject into processes not protected by DACL, call OS capture APIs, use accessibility APIs. |
| ADV-P | **Privileged malware / root / admin** | Full control of the client OS. |
| ADV-Q | **Harvest-now-decrypt-later quantum adversary** | Records all traffic today; breaks X25519/Ed25519 in the future. |
| ADV-AQ | **Active quantum adversary (future)** | Can break classical signatures/DH in real time. |
| ADV-L | **Legal compulsion** | Forces the relay operator (or hoster) to hand over data or to start logging. |
| ADV-S | **Supply-chain attacker** | Compromises a dependency, a toolchain, a CI runner, or a registry account. |
| ADV-H | **Physical observer** | Camera pointed at the screen, HDMI capture device, shoulder surfer. |
| ADV-U | **Coercion of the user** | Forces the user to unlock the device and show history ("show me your phone"). |
| ADV-RG | **Relay + Tor guard collusion** | The relay operator also observes (or is) the user's Tor entry guard, or a global passive observer correlates guard-side and relay-side traffic. |

## 3. What each adversary can and cannot learn (v1)

### 3.1 ADV-R — Relay operator

| Cannot learn / do | Why |
|---|---|
| Message content, message length, message type, whether a cell is real or cover traffic | Cells are E2E encrypted with encrypted headers and fixed size; dummies are ratchet messages (spec §7, §10) |
| Sender identity, recipient identity, any long-term key of any user | No identifiers exist; queue keys are per-queue pseudonyms; identity keys only appear inside E2E/invitation-encrypted blobs, with an inner layer keyed by ephemeral material so that even a later invitation leak does not expose the invitee's identity to a recording relay (spec §6.4–6.5) |
| Which two queues form a conversation — **cryptographically** | `rid` and `sid` are independent derived ids; in Strict mode every queue is reached over its own Tor circuit; identical `HandshakeInit` cells are indistinguishable from other cells |
| Client IP addresses (Tor mode) | Onion service; the relay sees only the rendezvous circuit |
| Content of invitations / prekeys | Link data is encrypted with a key the relay never sees |
| Partition users by handing out per-user relay keys or access keys undetected | `RelayInfo` is fetched per link and never cached; the access-key commitment `akc` is pinned in every `RelayRef` (spec §5.3, §8.2, §9.6) |
| Modify or inject messages undetected | Ratchet MAC with session binding; capability signatures on commands |
| Downgrade any cryptography | No negotiation exists |
| Destroy sessions by restarting | Queue ids are derived from keys and re-creatable (spec §9.1) |
| Comply with a demand for past traffic | RAM-only, no logs (see ADV-L) |

| Can learn / do (accepted) | Mitigation / note |
|---|---|
| Per-queue online periods (constant-rate streams start and stop) | Inherent to store-and-forward with a live client; documented in UI |
| **Statistically, over time, which queues belong to one client and which two form a conversation** (links of one client start after the same app start, stop at the same exit, rotate together; setup sequences such as invitation-get → three sends → new queue are timed chains; both queues of a conversation show mirrored online periods) | Reduced by spec §10.6 (random link phases and lifetimes, control operations on delayed one-shot links, queue pools, rotation overlap); *not* eliminated. With an anonymity set of two (v1) the operator already knows both users; the residual value of this leak grows with the user base and must be re-assessed then (RR-11). |
| Number of cells in a queue, eviction events | Inherent to being the store |
| In Balanced/Low-bandwidth mode: which queues share one client | User-selected trade-off; default is Strict |
| In direct (non-Tor) mode: client IP | Direct mode is opt-in with a warning |
| Rare control operations (create queue, put/get invitation) from anonymous circuits | Inherent |
| Deny service: drop cells, delete queues, refuse tokens | Availability only; detected via `Content.seq` gaps and `ERR_NOQUEUE`; v1.1 adds independent routes |
| Statistical disclosure over long periods across many users if the anonymity set is tiny | v1 has an anonymity set of two; the operator knows both users use the relay. Unobservability (when/how much) still holds. |

### 3.2 ADV-N — Network observer

| Cannot learn | Why |
|---|---|
| Content, sizes, activity | Fixed frames at constant rate inside Tor (or TLS) |
| That a given IP talks to a given relay (Tor mode) | Onion routing; the guard sees "Tor", the relay's guard sees "an onion circuit" |
| Anything from the PQ link layer later, even after breaking Tor's classical crypto | SecMP-LINK is hybrid PQ (spec §8.3) |

| Can learn (accepted) | Note |
|---|---|
| That the user uses Tor, and roughly constant traffic volume | Pluggable transports (WebTunnel/obfs4 via Arti `pt-client`) are a v1.x option |
| A global passive adversary correlating a user's guard traffic with the relay's guard traffic over long periods | Out of scope for Tor itself; constant-rate traffic on both sides removes the timing signal that makes this cheap |

### 3.3 ADV-C — Malicious contact

| Cannot | Why |
|---|---|
| Learn the user's IP | Tor; no direct connections in v1 |
| Learn the user's other contacts or their relays | Nothing shared |
| Replay, reorder undetectably, or inject into other sessions | Ratchet counters, session binding, key commitment |
| Trigger silent receipts or presence signals | No automatic responses except in-slot delivery receipts, which are constant-rate anyway |
| Impersonate a third party | Every session is a separate pairwise key agreement with verified fingerprints |
| Exhaust one-time prekeys | One OPK per invitation; no public bundle endpoint in v1 |

| Can (accepted) | Note |
|---|---|
| Screenshot or copy content they legitimately received on *their* device | See §4 — mitigated on their client by the same measures; content-level controls (view-once, expiry, watermark) reduce value |
| Flood the user's queue (until eviction/quota) | Per-queue capacity; user can rotate or delete the queue |
| Learn the user's online periods indirectly (delivery receipts) | Receipts to verified contacts only; can be disabled |

### 3.3a ADV-RG — Relay + guard collusion / global passive observer

Constant-rate traffic on both the client side and the relay side removes the *timing* signal that makes guard↔relay correlation cheap; what remains is coarse online-period correlation, which Tor itself does not defend against. Mitigation is the user base and, later, a mixnet transport (Nym) behind the `QueueTransport` trait. Recorded as RR-11.

### 3.3b ADV-U — Coerced user

Not preventable. Reduced by: per-message expiry, view-once content that never persists, a short default retention (owner decision OQ-10), and a "panic wipe" of the master key file (v1.x). No duress passwords in v1 (they create a false sense of security).

### 3.4 ADV-I — Invitation thief

Can become the invitee of that invitation (if faster than the intended one). Cannot impersonate the inviter (no inviter secret key in the invitation), cannot read the intended invitee's data. Mitigations: one-time consumption with detection (spec §5.2, §9.4), short expiry, mandatory safety-number verification before the contact is marked verified, and the UI marks unverified contacts loudly. Residual: social-engineering risk if the user verifies carelessly.

### 3.5 ADV-T — Device thief (offline)

Cannot read the store without the passphrase (Argon2id, 256 MiB) and/or the OS keystore/TPM-sealed key. Cannot decrypt past traffic (FS). Cannot impersonate the user without the store key. Residual: weak passphrase; therefore passphrase strength meter and optional TPM binding; "panic wipe" of the master key file is a v1.x feature.

### 3.6 ADV-M — Same-user malware

This adversary defines the boundary of the screen-capture requirement (see §4). Can: read the user's files (encrypted store is useless without the key, but the running process holds keys in memory), read process memory unless the process DACL / `PR_SET_DUMPABLE` forbid it, call capture APIs (defeated by `WDA_EXCLUDEFROMCAPTURE` on Windows; on GNOME/KDE Wayland an unprivileged client cannot read our buffers, but it can clear our compositor exclusion settings and then use the portal, and on wlroots compositors it may bind screencopy directly), scrape text through accessibility APIs (mitigated by the a11y policy, `04-client-security.md` §5), inject into the process (mitigated by DACL, CFG, extension-point disable, AppContainer in v1.x). Cannot be *fully* defeated: a user-level compromise of the endpoint is a partial compromise of the messenger. The design goal is to make the cheap, generic attacks (screen capture APIs, clipboard, a11y scraping, memory dumps) fail and to force the attacker into targeted, detectable techniques.

### 3.7 ADV-P — Root / admin malware

Out of scope for prevention. Design goals under this adversary: forward secrecy limits the blast radius to the future; post-compromise security (hybrid ratchet step) heals sessions once the attacker loses access; no data about *other* users beyond the victim's contacts exists on the device.

### 3.8 ADV-Q / ADV-AQ — Quantum

HNDL confidentiality is covered at every layer (HX, TR, LINK; TLS in direct mode). Authentication remains classical: an *active* quantum adversary in the future could impersonate parties in *new* handshakes. Accepted for v1 (same as Signal, Apple, Session V2 plans); PQ signatures already protect prekey bundles, and the identity key set is hybrid so that PQ authentication of bundles can become mandatory without a key change. Tracking item: KEM-based deniable AKE designs (K-Waay, RingXKEM) for v2.

### 3.9 ADV-L — Legal compulsion

The operator cannot hand over what does not exist: no accounts, no IPs (onion ingress), no logs, no persisted cells, no timestamps finer than hour buckets that are only used for expiry. A compelled *future* logging order would yield only: onion circuit arrivals, opaque fixed-size frames, per-queue online periods. The design deliberately makes compliance technically impossible rather than a matter of policy ("can't, not won't"). Legal status of a private, non-commercial relay under TKG/TDDDG and the pending German IP-retention bill is noted in research R2 §9; not legal advice.

### 3.10 ADV-S — Supply chain

Controls in `06-engineering-standards.md`: allowlisted dependencies with cargo-vet audits, 7-day cooldown, pinned toolchain, reproducible builds verified on two independent builders, SLSA L3 provenance *plus* an offline maintainer signature, SBOM per release, no `pull_request_target`, SHA-pinned actions, ephemeral Windows runner without secrets. Residual: a compromised upstream crate that survives cooldown and vet review; mitigated by the small dependency surface (crypto crates only in `secmp-crypto`) and differential testing against second implementations.

### 3.11 ADV-H — Physical observer

Not preventable by software. Reduced by: blur/hide when unfocused, view-once with hold-to-reveal, per-recipient visible watermark, short display windows, no notification previews.

## 4. The screen-capture threat, precisely

Requirement as stated: "immune to screenshot attacks". What SecMPro v1 commits to:

| Capture vector | Windows 10/11 | Linux Wayland | Linux X11 |
|---|---|---|---|
| PrintScreen, Snipping Tool, Game Bar, Windows.Graphics.Capture, BitBlt/PrintWindow, DXGI Desktop Duplication, screen-sharing apps (Teams/Zoom/OBS), Windows Recall / Copilot Vision | **Prevented** (`WDA_EXCLUDEFROMCAPTURE` + `DXGI_SWAP_CHAIN_FLAG_DISPLAY_ONLY`, re-applied and verified) | Ordinary Wayland clients cannot read our buffers (on GNOME/KDE; **wlroots-based compositors expose screencopy to any client unless a security context restricts it**). Portal/compositor screencast and screenshots: **prevented** on KDE Plasma ≥ 6.7 (6.6 covers screencasts only), Hyprland ≥ 0.50, niri (except niri's built-in screenshot UI) via exclusion rules the app installs or asks the user to install; **not preventable** on GNOME (no exclusion feature) and unknown compositors → **locked mode by default** with a per-session override | **Not preventable** (any client can read the root window) → **locked mode by default** with a per-session override |
| Same-user code injected into the SecMPro process that clears the flag (IOActive 2026 on Signal Desktop) | **Mitigated** (process DACL with OWNER RIGHTS ACE denies `PROCESS_VM_WRITE`/`CREATE_THREAD`/`WRITE_DAC` to other processes; mitigation policies; a watchdog re-applies and verifies the flag every 250 ms and alarms if it was cleared) — not prevented against admin | **Not prevented**: the Linux exclusions are compositor *settings* (KWin property, Hyprland/niri config) that same-user malware can clear before capturing; the client polls the exclusion state every 2 s and locks content with an alarm if it disappears (best effort) | n/a |
| Accessibility-API text scraping (UIA / AT-SPI) | **Mitigated**: message content is not exposed to the accessibility tree unless the user enables "accessibility mode" (explicit, persistent warning) | same | same |
| Remote desktop (RDP/VNC) rendering | **Mitigated**: remote session detected (`SM_REMOTESESSION`); content locked until the user overrides | Wayland: VNC servers use the same capture path (prevented where exclusion exists) | not preventable |
| Clipboard | **Mitigated**: copy disabled for view-once; history/cloud exclusion formats; auto-clear | same (KDE password-manager hint) | same |
| HDMI capture card, phone camera, shoulder surfing | **Not preventable** — deterred by view-once/hold-to-reveal, blur on unfocus, watermark | same | same |
| Admin/root malware, kernel-level capture | **Not preventable** | same | same |

Therefore the product wording MUST be: *"On Windows, SecMPro removes its windows from the operating system's capture APIs (GDI, DXGI duplication, Windows.Graphics.Capture, Recall). On Linux/Wayland it removes them where the compositor supports exclusion (KDE Plasma ≥ 6.7 — 6.6 for screen sharing only —, Hyprland, niri except its built-in screenshot tool); these exclusions are compositor settings and do not stop malware running as the same user. Elsewhere (X11, GNOME, unknown compositors, remote sessions) message content is locked by default. No software can stop a camera or a compromised operating system; view-once messages, blur-on-unfocus and watermarks reduce the value of what such an attacker could capture."* The word "immune" is not used in product text; the UI's security page states the limits.

## 5. STRIDE per trust boundary (summary)

| Boundary | S (spoofing) | T (tampering) | R (repudiation) | I (info disclosure) | D (DoS) | E (elevation) |
|---|---|---|---|---|---|---|
| Client ↔ relay link | Relay pinned by fingerprint; client anonymous by design | AEAD frames, counters | n/a (anonymous) | PQ hybrid link inside Tor; fixed frames | Per-link rate limits; Tor PoW; queue capacity | Relay process sandboxed |
| Relay ↔ queue store | Capability signatures | Relay is the store (trusted for availability only) | n/a | Cells opaque | Memory budget; eviction | n/a |
| Contact ↔ contact (E2E) | HX authentication + SAS | Ratchet MAC + session binding + key commitment | Deniable by design (no signatures on messages) | Encrypted headers; padding | Per-queue capacity | n/a |
| Invitation channel | Fingerprint commitment; SAS | Link data AEAD + COM | n/a | Invitation-key encryption of HandshakeInit | One-time consumption; expiry | n/a |
| UI ↔ core | n/a (in-process) | n/a | n/a | UI holds no keys; screen security | n/a | v1.x process split |
| Store ↔ disk | n/a | SQLCipher HMAC | n/a | Encrypted, wrapped keys, no temp files | n/a | n/a |

## 6. LINDDUN privacy threats (summary)

Linkability: queues unlinkable in Strict mode; identity keys never on the relay. Identifiability: no identifiers; invitations carry only a fingerprint commitment. Non-repudiation: avoided (deniability). Detectability: activity hidden by constant rate; Tor use itself detectable (pluggable transports later). Disclosure of information: E2E + PQ. Unawareness: the UI shows a "what the relay can see" page and explicit warnings for Balanced/direct modes and for unprotected displays. Non-compliance: no personal data is processed by the relay at all.

## 7. Residual risks register (must be reviewed at every release)

| # | Risk | Severity | Owner / plan |
|---|---|---|---|
| RR-1 | Anonymity set of two in v1; the operator knows both users | High (inherent) | Documented; grows with users; v1.1 removes the relay for online peers |
| RR-2 | GNOME Wayland has no capture exclusion | Medium | Locked mode + user guidance; track wayland-protocols MR !450 / xdg-desktop-portal-gnome #219 |
| RR-3 | Admin-level capture/injection on Windows | Medium (out of scope) | Watchdog + alarm; documented |
| RR-4 | Classical authentication only (ADV-AQ) | Low today | Hybrid IKS in place; PQ-AKE tracked for v2 |
| RR-5 | RAM-only relay: every restart loses undelivered cells (re-sent from outboxes) and briefly exposes a burst of re-creation commands | Low | Deterministic queue ids (spec §9.1); random re-creation delays |
| RR-11 | Statistical correlation of a client's queues and of conversation pairs through lifecycle timing (start/stop/rotation) | Medium (grows in importance with the user base) | §10.6 mitigations; re-assess at 100+ users; mixnet transport option |
| RR-12 | Linux capture exclusions are user-space settings; same-user malware can clear them | Medium | Poll-and-lock heuristic; Flatpak sandboxing (v1.x); honest wording |
| RR-13 | Handshake envelope exposure if an invitation leaks *and* the relay recorded the cells: only the outer layer is affected; identity stays protected by `K_id` once the OPK is deleted | Low | Spec §6.4–6.5 |
| RR-14 | Eviction notices tell a contact that the recipient was offline for longer than `QUEUE_CAPACITY × P_q` | Low | Documented; receipts reveal the same |
| RR-6 | Constant-rate traffic cost may push users to Low-bandwidth mode (weaker) | Medium | Measure in M6; tune `T`/`F` |
| RR-7 | Arti (client) is pre-1.0 with breaking API changes | Medium | Pinned version + CI upgrade job |
| RR-8 | Unaudited pure-Rust ML-DSA / ML-KEM crates | Medium | Differential tests vs second implementations; KATs on every target; external audit before 1.0 |
| RR-9 | Accessibility trade-off (screen readers vs scraping) | Medium | Explicit opt-in mode with warning; consult a11y users before 1.0 |
| RR-10 | Invitation shared over a compromised channel | Medium | One-time + expiry + SAS mandatory |
| RR-15 | **LinkDataV1 profile/created and bundle metadata not transcript-bound (O-10, M4).** `Profile_R`/`created` in LinkDataV1 and `spk_expiry`/`opk_present`/`sig` are bound only by K_ld and the bundle signature, not by the HX transcript; an invitation holder can substitute the inviter's Profile. Accepted for v1; binding at the next breaking spec revision (v2). | Low (accepted for v1) | Binding at the next breaking spec revision (v2) |
| RR-17 | **Processing-time leakage on the TR receive path (M3 review R-15).** The time `Decrypt` takes reveals the reject reason, step vs chain, the gap size, pending skipped entries, dummy vs real and the accept-path position; §9.3's ack ("whatever ack is committed by then") can make it network-visible. | Medium (until F24) | STOP-class requirement for M6: ack timing independent of processing duration (F24) |
| RR-18 | **Fast-forward CPU cost (M3 review R-16).** A contact's cell with large `n`/`pn` costs up to 2^21 + 1 `KDF_CK` (≈ 0.87 s) before the body MAC, discarded on reject and replayable by the relay without limit. | Low (availability) | M6/M7 per-session fast-forward budget (F25); the handshake's first message admits no fast-forward (M4 review C-9) |
| RR-19 | **Skipped-key retention without expiry (M3 review R-17).** A relay that drops one cell per chain keeps up to 512 message keys of recorded cells stored for a later compromise of the device; forward secrecy holds for those cells only once their keys leave `skipped`. | Medium | M7 age bound / write budget (F28) |

**Opening-trial position (R-59, M4).** On the TR receive path the position of the header-key trial that opens leaks about one timer floor — ≈ 59 ns on Apple M1 Pro — through the AEAD library's tag-check branch (measured 2026-10-01 on the M1 Pro: −1.4 floors first vs last candidate, reject path). Accepted under RR-17 (processing-time leakage), pending F24 (M6: ack timing independent of processing duration); hardening scheduled: branch-free trial opens (F-M5).
