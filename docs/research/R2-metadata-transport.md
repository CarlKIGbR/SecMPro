---
title: "R2 — Metadata protection and transport (research brief)"
date: 2026-09-25
status: research input (not normative; the normative documents are docs/02-architecture.md, docs/03-protocol-spec.md and docs/08-decisions.md)
---

# SecMPro: research brief on metadata-private messaging (state as of 2026-09-25)

I checked every item below against live sources fetched this session. Where a source was secondary or incomplete I mark it UNVERIFIED. Version numbers and dates are the ones the sources gave on 2026-09-25.

**Framing for v1:** the setup is one server and two clients, so the anonymity set is 2. The server operator will always know that these two people use it. What v1 can still hide is:
- **Unobservability:** when messages are sent, how many, how big, and whether anything is being sent at all.
- **Unlinkability:** network location (IP address) cannot be tied to mailbox or queue identities.
- **Capability to leak:** the protocol should make it structurally impossible to produce logs. The design should still scale to many users.

---

## 1. SimpleX (SMP, XFTP, notifications)

**Facts**
- **Releases:** stable app 6.5.x (6.5.0 on 2026-04-30, 6.5.3 in May 2026). 7.1.0-beta.4 came out on 2026-09-19 and adds "SMP-v22" support. The SMP spec page shows version 20, dated 2026-05-25.
- **Queue model:** queues are one-way ("simplex") and created by the recipient.
  - The `NEW` command carries the recipient's auth key (Ed25519), a recipient DH key for a server-to-recipient encryption layer, and optionally a notifier key.
  - The server returns separate random IDs: a recipient ID (RID) and a sender ID (SID). A separate notifier ID (NID) is used for notifications. This means the sender and recipient sides share no identifier.
  - The sender receives the SID and keys out of band. Since v9, `SKEY` lets the sender secure the queue right away.
  - Flow: `SEND` is signed with the sender's key. `MSG` is re-encrypted by the server to the recipient's DH secret, so incoming and outgoing ciphertext cannot be matched. The server deletes a message only after `ACK`.
- **Sizes:** all transport uses fixed 16,384-byte blocks. The maximum message is 16,048 bytes.
- **Normative no-logging rules:** routers MUST NOT keep logs of commands or connections, a history of deleted queues or messages, or database snapshots.
- **Agent protocol (v7, 2025-01-24):**
  - A two-way connection is made of two or more one-way queues.
  - Queue rotation uses QADD, QKEY, QUSE and QTEST.
  - E2E encryption is a post-quantum double ratchet using sntrup761, added in v5.6 (March 2024).
- **Private message routing (v5.8, 2024-06-04):** two hops.
  - The sender picks the forwarding relay; the recipient picks the destination relay (commands PRXY, PFWD, RFWD).
  - Encryption layers: s2d, f2d, d2r, plus TLS. The forwarding relay does not see the queue, and the destination relay does not see the sender's IP.
  - It was not on by default at launch.
- **XFTP (files):**
  - Fixed chunk sizes of 64 KB, 256 KB, 1 MB and 4 MB.
  - Each recipient gets its own chunk IDs, and the recipient count is padded to a power of two.
  - The file description (locations and keys) travels over SMP. Chunks are spread across several servers.
- **Notifications:** a separate NTF server learns the device token, how many queues a user has and how often notifications fire. It does not learn queue addresses. APNs sees only counts.
- **Threat model (security.md):** the router *can* do three things:
  - see when a recipient is online;
  - count messages per queue;
  - "correlate the queue used to receive messages via either a re-used transport connection, user's IP Address, or connection timing regularities."
- **Short links (v6.4, 2025-07-03):**
  - Link data is encrypted with `secret_box` under a key taken from the URI. The key is separate from the link ID the server knows.
  - The link data is signed (SHA3-256 hash plus Ed25519).
  - One-time links lock the queue after first access, which warns the owner if someone else opened it.
- **Audits (Trail of Bits):**
  - Nov 2022: implementation assessment.
  - Jul 2024: cryptographic design review with 7 findings (3 medium, 1 low, 3 informational).
    - "Compromised TLS" (medium): SimpleX responded by adding a transport encryption layer *inside* TLS.
    - Traffic correlation: accepted as part of the threat model; randomised latency is being considered.
  - An implementation assessment was scheduled for June 2026. Whether it has been completed is UNVERIFIED.

**Recommendations for SecMPro (adopt)**
- **Queues:** use one-way queues with independent random RID, SID and NID. Keep no account and no user ID anywhere.
- **Sender authorisation:** authorise senders per queue with a capability key (SKEY-style). The server then knows only that "someone holding the key wrote this."
- **Server re-encryption:** re-encrypt from server to recipient so the bytes that arrive never equal the bytes that leave.
- **Fixed size and no logs:** make the fixed transport cell and the no-log rules normative MUSTs in your spec, as SMP does.
- **Rotation:** rotate queues periodically and invisibly.
- **Invitations:** use one-time invitation queues that lock on first read, with encrypted link data.

**Adapt rather than copy**
- Use ML-KEM-768 (FIPS 203) instead of sntrup761.
- With a single server, SimpleX's own threat model says it can link a client's queues through connection reuse or timing. Counter this with per-queue circuit isolation and constant-rate rounds (§3 and §5).

---

## 2. Signal's metadata mitigations

**Facts**
- **Sealed Sender (2018-10-29):**
  - The server issues a short-lived certificate (identifier, identity key, expiry), which is encrypted to the recipient.
  - A 96-bit delivery token derived from the profile key limits sealed messages to contacts, as an anti-abuse measure.
  - The server still sees the recipient, the sender's IP and the timing.
- **Martiny et al., "Improving Signal's Sealed Sender" (NDSS 2021):**
  - Delivery receipts (on by default) make a statistical disclosure attack possible. Senders and recipients can be linked "in as few as 5 messages."
  - Proposed fix: ephemeral one-way or two-way "sealed conversations" with mailboxes authenticated by blind signatures, costing under $40/month at scale.
- **Careless Whisper (arXiv 2411.11194; RAID 2025 Best Paper):**
  - Crafted messages trigger *silent* delivery receipts on Signal and WhatsApp.
  - This leaks online status, screen on/off, device count and OS, and can drain battery.
- **Signal-Android issue #13842 (2024-12-13):** on HTTP 401 the client silently falls back from sealed to unsealed sending. A malicious server could strip sender protection this way.
- **Contact discovery (CDSI, 2022-08-19):** runs in SGX with Path ORAM.
  - V12 (2026-08-26) reported two critical enclave bugs, a use-after-free and a TOCTOU race.
  - These allowed extracting the enclave's Noise private key and gaining code execution inside it. Signal has fixed them.
- **Secure Value Recovery:**
  - SVR3 (OSDI 2024) splits trust across different enclave types: SGX, SEV-SNP and Nitro.
  - Secure Backups (2025-09-08) instead use a 64-character recovery key generated on the device, plus zero-knowledge credentials so backups are not linked to accounts.
- **Private Group System (blog 2019-12-09; CCS 2020, eprint 2019/1416):**
  - The server stores encrypted membership entries.
  - Members prove membership using keyed-verification anonymous credentials (KVAC, algebraic MACs) and zero-knowledge proofs.
  - **No SGX is needed.** Signal ships this as zkgroup inside libsignal, which is licensed AGPL-3.0.
- **Post-quantum:** PQXDH (2023), then SPQR, the ML-KEM-768 "Braid" or Triple Ratchet (2025-10-02). SPQR erasure-codes KEM chunks across messages and is formally verified with ProVerif and F*.

**Recommendations for SecMPro**
- **Sealed sender:** use no sender certificate at all. The capability-queue model is stronger than Sealed Sender because the server never needs to know who the sender is.
- **No enclaves:** do not rely on SGX or other TEEs. Given the 2026 CDSI bugs, treat enclaves as defence in depth at best.
- **Anonymous credentials:** use KVAC-style credentials (the Signal/Chase-Perrin-Zaverucha approach) later, for group management and anonymous quota. They run on one ordinary server.
- **Receipts are metadata:**
  - E2E only.
  - Padded and sent only in constant-rate slots.
  - Off by default.
  - Never triggered by messages the user cannot see.
- **Fail closed:** never silently downgrade privacy protections (the #13842 lesson).
- **PQ ratchet:** copy SPQR's pattern: a hybrid ratchet, with ML-KEM material spread across messages.

---

## 3. Traffic-analysis resistance

**Facts**
- **Padmé (PURBs, PETS 2019):** leaks O(log log M) bits of length information with at most 12% overhead.
- **Loopix (Piotrowska et al., 2017):**
  - Poisson mixing (exponential delays), loop and drop cover traffic, and providers that store messages for offline clients.
  - Latency is on the order of seconds.
- **Nym:**
  - Topology: entry gateway, three mix layers, exit gateway. Anonymous replies use SURBs (single-use reply blocks).
  - Rust `nym-sdk` 1.21.6 was published 2026-09-04. It is not feature-gated yet and pulls in all modules.
  - NymVPN "Mixnet Tuning" (blog 2026-07-14) defaults: about 15 ms mean delay per hop, a packet about every 20 ms, a cover packet about every 200 ms. That costs roughly 1 Mbps steady plus tens of ms of latency. It can be tuned up to 200 ms per hop and 0.7–2 Mbps of cover.
  - Whether SDK use needs paid zk-nym credentials is UNVERIFIED.
  - Echomix/Katzenpost (arXiv 2501.02933, Jan 2025) is a post-quantum hybrid mixnet written in Go. It may be what you meant by "Echo" (UNVERIFIED).
- **Tor via Arti:**
  - Arti 2.6.0 was released 2026-09-01; `arti-client` 0.46.0 on 2026-09-02, so it is still pre-1.0.
  - Arti 2.0.0 (2026-02-02) marked the `arti` crate APIs experimental.
  - Arti 2.5.0 (2026-06-30) made Counter Galois Onion (CGO, the new relay encryption) stable and congestion control the default. It fixed TROVE-2026-024 and -027 (DoS).
  - **Onion-service client** (`onion-service-client`, a default feature): vanguards since 1.2.2, PoW client since 1.3.0, restricted discovery stabilised in 1.7.0 (2025-11-03).
  - **Hosting** (`onion-service-service`): has gaps. Offline keys are missing, and some defences are still marked experimental per the onionservices.torproject.org implementations page.
  - **Library caveats:**
    - APIs are unstable until 1.x.
    - The library can call `exit(1)` if the consensus says it is obsolete.
    - The process must not fork after the runtime starts.
    - It must be kept updated.
  - Pluggable transports work through `pt-client` using external PT binaries.
- **I2P:** `emissary` (Rust) is at 0.2.x. It is early-stage, and SSU2 is experimental. Not recommended.
- **PIR in 2025–26:**
  - Speed: SimplePIR runs at about 12 GB/s and YPIR at about 5 GB/s, near memory bandwidth.
  - Communication is still O(√N); for example about 1.5 MB upload for an 8 GB database. Linear scan limits practical use to roughly 100 GB or less. Apple ships PIR-style lookups (per D. Wu, June 2025).
  - Messaging systems:
    - Pung (OSDI 2016): single-server PIR; heavy.
    - Express (USENIX Security 2021): two servers, DPF.
    - DPIR (CCS 2024): offloads PIR work to clients.
    - Myco (IEEE S&P 2025): two-server oblivious structure, up to 2,219× over single-server PIR.
    - PingPong (arXiv 2504.19566, 2025): needs SGX, and its proof assumes constant client traffic that the code does not send.
  - **Verdict:** single-server PIR messaging is not production-practical. Strong schemes need two or more non-colluding servers or TEEs.

**Recommendations for SecMPro**
- **v1 transport:** host the server as a v3 onion service using C tor on the server (more mature). On clients, embed Arti (`arti-client` with `onion-service-client`, pinned version, CI upgrade pipeline). A C-tor sidecar is an acceptable fallback.
- **Isolation:** use a separate isolated Tor circuit per queue, or per round, to limit the SimpleX-described correlation by connection reuse.
- **Constant-rate loop on each client:**
  - Every T seconds, send exactly one fixed-size cell (a real message or a dummy to your own drop queue) and do exactly one fetch round.
  - Cost: 4 KiB every 30 s is about 11.8 MB/day per direction; 16 KiB every 10 s is about 142 MB/day. Both are fine on desktop.
  - Latency: at most T plus Tor round-trip time.
- **Padding:** messages use one fixed cell size. Files are chunked into XFTP-like size classes, with Padmé on the total length.
- **Small user counts:** "fetch everything" (trivial PIR, as Cwtch does) is cheap and strong. It needs a protocol design where clients trial-decrypt fixed-size slots.
- **Later:** keep a pluggable transport trait so a Nym (SDK) transport can be added. No mixnet in v1.

---

## 4. Transport layer

**Facts**
- **rustls:**
  - Currently 0.23.45 (2026-09-14).
  - Default features include `aws_lc_rs` and `prefer-post-quantum`, so X25519MLKEM768 is the top-priority key exchange by default with aws-lc-rs.
  - The ring provider has no ML-KEM. Pure MLKEM768 is off by default.
  - History:
    - 0.23.22: ML-KEM moved into the main crate.
    - 0.23.37: added ML-KEM-1024.
    - 0.23.44 (2026-09-07): ML-DSA certificates enabled by default (private PKI only).
  - 0.24 (split mode, decoupled providers) and then 1.0 are coming.
- **quinn:** 0.11.11 (docs.rs date 2026-06-22) depends on rustls ^0.23.5. A quinn-proto 0.11.15 security release fixed remote memory exhaustion in the Assembler.
- **0-RTT:** early data is replayable and not forward-secret (RFC 8446 §8; RFC 9001 §9.2).
- **Connection migration:** connection IDs must not be linkable across paths (RFC 9000 §9.5).
- **Tor carries only TCP streams.** QUIC/UDP cannot run over onion services.
- **Censorship:**
  - China's Great Firewall has blocked QUIC by decrypting the Initial packet's SNI since 2024-04-07. It ignores flows where the source port is at or below the destination port and cannot reassemble multi-datagram Initials (GFW Report, USENIX Security 2025).
  - Iran blocked UDP/QUIC (2021); Russia blocked some QUIC versions (2022).
  - China, April 2025 (Tor forum user report): obfs4, meek and Snowflake were unusable; WebTunnel connected but was blocked within minutes.
  - WebTunnel (2024-03-12) imitates HTTPS/WebSocket and can share a domain with a real website.
- **Noise with post-quantum:**
  - PQNoise (Angel, Dowling, Hülsing, Schwabe, Weber; CCS 2022; eprint 2022/539) replaces DH with KEMs, using `ekem` and `skem` tokens.
  - `snow` 0.10.0 (2025-07-19) is unaudited. Its hybrid forward secrecy (HFS) extension historically used Kyber1024; PR #210 to add ML-KEM-768 is still open.
  - `clatter` 1.x (first stable 2024-11-15) is pure Rust with PQ and hybrid "DualLayer" handshakes. It is unaudited and still defaults to Kyber.
  - NoisePQC++ (arXiv 2608.00954, 2026-08-02) recommends hybrid as the default.
  - X-Wing KEM (X25519 plus ML-KEM-768) is draft-connolly-cfrg-xwing-kem-11. It is an individual/ISE submission, not yet an RFC.

**Recommendations for SecMPro**
- **Layering (defence in depth, as Trail of Bits pushed SimpleX to do):**
  - Outer: Tor, or TLS 1.3 in direct mode.
  - Inner: a server-authenticated Noise handshake with the server's static key pinned in the invitation. Use a hybrid IK/XX pattern with X25519 plus ML-KEM-768 (X-Wing-style combiner).
  - Innermost: E2E hybrid ratchet.
- **Why the inner PQ layer is required:** Tor's circuit handshake is not post-quantum, so without it, harvest-now-decrypt-later attacks on transport metadata would work.
- **Direct mode:** QUIC plus rustls 0.23 with aws-lc-rs (X25519MLKEM768 by default). Disable 0-RTT. Rotate connection IDs.
- **Fallback:** TLS/TCP on 443 with ordinary ALPN. Later, WebTunnel-like HTTPS camouflage, or Tor pluggable transports through Arti.
- **Noise implementation:** avoid depending on unaudited PQ Noise crates as-is. Either implement a minimal fixed pattern using the RustCrypto `ml-kem` crate plus `x25519-dalek`, and model it in ProVerif or Tamarin, or fork `snow` with HFS/ML-KEM-768. Budget for an audit.

---

## 5. Zero-knowledge relay design

**Facts**
- **Privacy Pass (June 2024):**
  - RFC 9576 (architecture), RFC 9577 (HTTP authentication), RFC 9578 (issuance).
  - Token 0x0001 is VOPRF(P-384) per RFC 9497 and privately verifiable. Token 0x0002 is blind RSA-2048 per RFC 9474 and publicly verifiable.
  - Neither is post-quantum.
- **Rate-limited credentials:** ARC (anonymous rate-limited credentials, a KVAC variant with per-context presentation limits) was drafted as draft-ietf-privacypass-arc-crypto/-protocol-01. Datatracker showed them as expired/"Dead WG Document" in Sept 2026. A successor such as draft-yun-cfrg-arc exists, but its status is UNVERIFIED.
- **Rust crates:** `voprf` 0.6.0-pre.0 (Nov 2025), `privacypass` 0.2.0-pre.0 (unstable), `blind-rsa-signatures`.
- **Proof of work:** Tor's onion-service PoW (Equi-X, Tor 0.4.8, 2023-08-23) gives DoS priority without identity. Arti clients support it.

**Recommendations for SecMPro**
- **No accounts:** writing requires a per-queue sender key; creating a queue requires an anonymous token.
  - The admin gives each invited user N VOPRF tokens (RFC 9578 type 1 is sufficient for a single issuer and verifier).
  - Redemption cannot be linked to issuance.
  - Later, ARC or KVAC can give a per-epoch quota.
- **Abuse control:**
  - Per-queue quotas, with a QUOTA error like SMP.
  - Recipients can delete or rotate queues at any time.
  - Onion-service PoW plus restricted discovery (client auth) so unauthorised parties cannot even reach the server.
  - With no global identifiers there is nothing to spam unless someone holds a capability.
- **Storage:**
  - Ciphertexts in RAM only, or in an append-only journal encrypted with a key generated at boot and held only in RAM. A restart then loses undelivered data by design.
  - Delete on ACK; TTL of 7–14 days; also expire idle queues. (SimpleX's defaults are about 21 days, UNVERIFIED.)
  - Harden the host: no swap or encrypted swap, core dumps off, no request logging at any layer (reverse proxy, systemd journal, tor), and no timestamps stored beyond the expiry bucket.
- **Timing decorrelation:**
  - Clients send at a constant rate (§3).
  - The server delivers in fixed epochs, for example releasing all messages accepted in epoch k at the start of epoch k+1.
  - Optionally add randomised per-message delay; SimpleX is also considering this.
  - Responses and ACKs are fixed-size and padded to cells.

---

## 6. Push, notifications and presence

**Facts**
- Push always creates a third-party observer (APNs/FCM) and a per-device token. SimpleX's NTF server can still count queues and see notification rates.
- Careless Whisper shows that anything the client emits *automatically* (receipts, reactions, typing indicators) acts as a remote ping for activity and device state.

**Recommendations for SecMPro**
- **Desktop v1 has no push.** A long-lived Tor connection runs the constant-interval loop, and the heartbeat *is* the fetch/send slot.
- **Keep patterns stable:** use the same cadence whether the app is focused, idle or minimised. Randomise the timing of the first connection after start-up. Add jitter to reconnects.
- **No presence features:** no online status, typing indicators or "last seen." Read and delivery receipts are off by default. If enabled, they are E2E, batched, and sent only in slots.
- **Mobile later:** use periodic background fetch or a self-hosted notifier that only receives "wake up" signals at a constant rate and contains no queue data (UnifiedPush-style). Document what it leaks.

---

## 7. Contact discovery without identifiers

**Facts**
- **SimpleX:** one-time invitation links or QR codes, and short links (2025). Users verify each other by comparing a security code.
- **Briar:**
  - In person: both sides scan each other's QR codes (Bramble QR Code Protocol).
  - Remotely: exchange `briar://` handshake links, then run the Bramble Handshake Protocol over Tor. These links must still be verified out of band.
  - The latest Android release is 1.5.9 (2024-01-16), so development is slow (source: Wikipedia; the spec site blocks automated fetches).
- **Cwtch:** the identity is a Tor v3 onion address, and there is no global name registry. Users "absolutely validate the public key." Group servers are untrusted and clients trial-decrypt.
- **Session:**
  - The Account ID is a public key, with an optional ONS name.
  - "Protocol V2," announced 2025-12-01, adds perfect forward secrecy, ML-KEM and per-device keys. The spec is expected in 2026. V1 had no PFS.

**Recommendations for SecMPro**
- **Invitation contents:** an invitation is a one-time capability URI (or QR) containing:
  - the server's .onion address and pinned Noise static key;
  - the one-time queue's sender ID and key;
  - an ephemeral PQ-hybrid prekey;
  - a commitment to the inviter's identity key.
  - Put all secrets in the URI fragment, give it an expiry, and lock it on first use.
- **How to share it:** in person by QR is best. Over an existing channel it is acceptable, provided the next step happens.
- **Mandatory check:** after the handshake, require verification with a short authentication string: 5–6 words or a 60-digit safety number, compared by voice or in person. Show "unverified" prominently until done.
- **Link data:** encrypted "link data" (profile, welcome message) sits on the server under a key the server never sees (SimpleX pattern).

---

## 8. Identity and account model

**Facts**
- **Signal's Sesame:** handles multi-device sessions. Cremers et al. (eprint 2021/626) showed clone detection failures in it.
- **Device linking is an attack surface:** Google Threat Intelligence (2025-02-19) documented Russian state actors (UNC5792, UNC4221, APT44) abusing Signal's "linked devices" with malicious QR codes. They also stole Signal Desktop databases from disk.
- **MLS virtual clients:** draft-ietf-mls-virtual-clients-01 (2026-07-06) lets a user's devices appear as one member, hiding the device count. The trade-off: compromising one device compromises all.
- **Recovery:** Signal Secure Backups use a key held only by the user plus anonymous credentials. Reports of phishing for recovery keys (TechTimes, 2026-07-27) are UNVERIFIED and come from a secondary source.

**Recommendations for SecMPro**
- **No accounts.** A "user" is only local state: a set of per-contact queues and keys, with optional pairwise identity keys. There is no global identity key.
- **Protect local state:** encrypt it (SQLCipher-style, key from a passphrase via Argon2id). This matters because desktop database theft is a documented technique.
- **v1 is single-device.** Recovery is an explicit, offline, encrypted export file. Nothing about recovery is stored on the server.
- **Keep multi-device possible:**
  - Model per-contact sessions so a "device group" can later share state (virtual-client style).
  - Linking must require on-device confirmation plus a short authentication string. Never link by just scanning a code.
  - Show linked devices prominently.

---

## 9. Legal context (DE/EU, only as it affects design)

- **Chat Control 1.0 (Reg. 2021/1232):**
  - It expired on 2026-04-03. The Council re-adopted it, and on 2026-07-09 an EP motion to reject got 314 votes, short of the absolute majority needed. It is now extended to 2028-04-03.
  - E2E-encrypted content (Signal, Threema, WhatsApp) is explicitly excluded (netzpolitik).
- **CSAR ("Chat Control 2.0"):**
  - The Council mandate of 2025-11-26 drops mandatory detection orders, keeps voluntary scanning, and adds risk assessment and mitigation duties.
  - The Parliament mandate dates from Nov 2023.
  - Trilogues are ongoing. A sixth trilogue on 2026-09-29 comes from a secondary source (UNVERIFIED). Whether client-side scanning becomes mandatory is undecided.
- **Germany, data retention:**
  - The cabinet bill of 2026-04-22 requires 3-month retention of IP addresses and ports by internet access providers.
  - It also creates preservation orders ("Sicherungsanordnung") that can apply to about 3,000 telecom providers, including email and messenger services.
  - First Bundestag reading was 2026-06-24 (Drucksache 21/6581); it is in committee.
- **TKG/TDDDG:**
  - Messengers count as "number-independent interpersonal communication services" under the TKG, and TKG duties apply to services "usually provided for remuneration."
  - § 5 TKG notification applies only to commercial providers, and these messengers have been exempt since 2021-12-01.
  - TTDSG was renamed TDDDG in 2024, and the BfDI (federal data protection commissioner) supervises telecom-type messengers.
  - A private, non-commercial, closed-group server is *likely* outside most TKG duties. GDPR applicability is still open. Legal advice is recommended (UNVERIFIED interpretation).
- **Design consequence:** the architecture should be structurally unable to comply ("can't, not won't"):
  - Ingress only via the onion service, so no client IP ever exists.
  - No sender identity.
  - Unlinkable queue IDs.
  - No logs and RAM-only state.
  - Then even a preservation order yields no useful traffic data.

---

## Open questions and uncertainties

1. **The v1 anonymity set is 2.** Unobservability through constant rate is achievable. Unlinkability of *who* the users are is not, until there are many users.
2. **Arti onion-service hosting maturity** compared with C tor; there is no explicit 2026 production statement. The exact current README caveats are UNVERIFIED.
3. **Nym SDK:** whether it needs credentials or payment, and its mainnet stability for a messaging app (UNVERIFIED).
4. **ARC and the successor to anonymous rate-limit tokens** (IETF status unclear); no post-quantum anonymous token is standardised.
5. **The PQ Noise implementation choice:** none of `snow` HFS, `clatter` or a custom build is audited. Formal verification scope and cost are unknown.
6. **Whether SimpleX's June 2026 Trail of Bits implementation audit happened**, and what it found (UNVERIFIED).
7. **Legal classification** of a private self-hosted server under the TKG, GDPR and CSAR's risk-mitigation duties (for example, age verification), and whether preservation orders could require logging going forward.
8. **The exact meaning of "Echo"** in the brief. The closest match found is Echomix/Katzenpost (UNVERIFIED match).
9. **Latency budget vs. cover-traffic cost:** the round interval T is a product decision.
10. **SMP version numbering:** the spec page shows v20 while app 7.1 references SMP v22. Both come from fetched pages, but the discrepancy is unresolved.

---

## Sources

- SMP spec: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- SimpleX overview: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/overview-tjr.md
- SimpleX threat model: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/security.md
- SimpleX agent protocol: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/agent-protocol.md
- XFTP: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/xftp.md
- SimpleX push notifications: https://github.com/simplex-chat/simplexmq/blob/stable/protocol/push-notifications.md
- SimpleX v5.8 private routing: https://simplex.chat/blog/20240604-simplex-chat-v5.8-private-message-routing-chat-themes.html
- Trail of Bits review 2024: https://simplex.chat/blog/20241014-simplex-network-v6-1-security-review-better-calls-user-experience.html
- SimpleX short links 2025: https://simplex.chat/blog/20250703-simplex-network-protocol-extension-for-securely-connecting-people.html
- SimpleX security page: https://simplex.chat/security/
- SimpleX 7.1.0-beta.4: https://freedom.tech/posts/2026-09-19-simplex-chat-7-1-0-beta-4/
- SimpleX Wikipedia: https://en.wikipedia.org/wiki/SimpleX_Chat
- Signal sealed sender: https://signal.org/blog/sealed-sender/
- Improving Sealed Sender (NDSS 2021): https://www.ndss-symposium.org/ndss-paper/improving-signals-sealed-sender/
- Careless Whisper: https://arxiv.org/abs/2411.11194
- Signal-Android #13842: https://github.com/signalapp/Signal-Android/issues/13842
- Signal CDSI/ORAM: https://signal.org/blog/building-faster-oram/
- V12 CDSI enclave bugs: https://v12.sh/blog/signal
- SVR3 (OSDI 2024): https://www.usenix.org/conference/osdi24/presentation/connell
- Signal Secure Backups: https://signal.org/blog/introducing-secure-backups/
- Signal backup key reports (UNVERIFIED): https://www.techtimes.com/articles/321712/20260727/signal-backup-recovery-key-flaw-exploited-russian-spies-gets-formal-cryptographic-fix-today.htm
- Signal Private Group System: https://signal.org/blog/signal-private-group-system/
- Private Group System paper: https://eprint.iacr.org/2019/1416
- SPQR: https://signal.org/blog/spqr/
- Sesame: https://signal.org/docs/specifications/sesame/
- Sesame clone-detection attacks: https://eprint.iacr.org/2021/626.pdf
- Google TIG linked-device attacks: https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger
- MLS virtual clients: https://datatracker.ietf.org/doc/draft-ietf-mls-virtual-clients/
- PURBs/Padmé: https://petsymposium.org/popets/2019/popets-2019-0056.php
- Loopix: https://arxiv.org/abs/1703.00536
- Nym cover traffic: https://nym.com/docs/network/mixnet-mode/cover-traffic
- Nym mixnet tuning: https://nym.com/blog/mixnet-tuning
- nym-sdk: https://docs.rs/nym-sdk/latest/nym_sdk/
- Nym Rust SDK tour: https://nym.com/docs/developers/rust/tour
- Nym FOSDEM 2026: https://archive.fosdem.org/2026/schedule/event/U3UCKS-nym-mixnet/
- Nym Wikipedia: https://en.wikipedia.org/wiki/Nym_(mixnet)
- Echomix: https://arxiv.org/abs/2501.02933
- Arti 2.6.0: https://blog.torproject.org/arti_2_6_0_released/
- Arti 2.5.0: https://blog.torproject.org/arti_2_5_0_released/
- Arti 2.0.0: https://blog.torproject.org/arti_2_0_0_released/
- Arti 1.8.0: https://blog.torproject.org/arti_1_8_0_released/
- Arti 1.7.0: https://blog.torproject.org/arti_1_7_0_released/
- Onion service implementations: https://onionservices.torproject.org/dev/implementations/
- arti-client docs: https://docs.rs/arti-client/latest/arti_client/
- arti crate: https://docs.rs/crate/arti/latest
- Tor onion-service PoW: https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services/
- WebTunnel: https://blog.torproject.org/introducing-webtunnel-evading-censorship-by-hiding-in-plain-sight/
- Tor China report, April 2025: https://forum.torproject.org/t/feedback-from-china-april-2025-increased-gfw-censorship-obfs4-meek-snowflake-unusable-webtunnel-connects-but-is-quickly-blocked/18233
- emissary-core: https://lib.rs/crates/emissary-core
- PIR state (D. Wu, June 2025): https://www.cs.utexas.edu/~dwu4/talks/PIR0625.pdf
- YPIR: https://eprint.iacr.org/2024/270.pdf
- InsPIRe: https://eprint.iacr.org/2025/1352
- DPIR: https://eprint.iacr.org/2024/978
- Myco: https://sky.cs.berkeley.edu/project/myco/
- PingPong: https://pith.science/paper/2504.19566
- Express: https://www.usenix.org/conference/usenixsecurity21/presentation/eskandarian
- rustls docs: https://docs.rs/rustls/latest/rustls/
- rustls features: https://docs.rs/crate/rustls/latest/features
- rustls-post-quantum: https://docs.rs/rustls-post-quantum/latest/rustls_post_quantum/
- A Decade of Rustls: https://rustls.dev/blog/2026-09-08-a-decade-of-rustls/
- Rustls 0.23.44 (Phoronix): https://www.phoronix.com/news/Rustls-0.23.44-Released
- quinn: https://docs.rs/crate/quinn/latest
- quinn releases: https://github.com/quinn-rs/quinn/releases
- RFC 9000: https://www.rfc-editor.org/rfc/rfc9000.html
- GFW QUIC SNI (USENIX Security 2025): https://gfw.report/publications/usenixsecurity25/en/
- PQNoise: https://eprint.iacr.org/2022/539
- NoisePQC++: https://arxiv.org/html/2608.00954v1
- snow: https://docs.rs/crate/snow/latest
- snow PR #210: https://github.com/mcginty/snow/pull/210
- clatter: https://lib.rs/crates/clatter
- X-Wing: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
- RFC 9578: https://datatracker.ietf.org/doc/rfc9578/
- RFC 9576: https://www.ietf.org/rfc/rfc9576.html
- RFC 9577: https://datatracker.ietf.org/doc/rfc9577/
- RFC 9497: https://datatracker.ietf.org/doc/rfc9497/
- RFC 9474: https://www.rfc-editor.org/rfc/rfc9474.html
- ARC protocol draft: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/
- ARC crypto draft: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/
- ARC CFRG draft: https://datatracker.ietf.org/doc/draft-yun-cfrg-arc/
- voprf crate: https://lib.rs/crates/voprf
- privacypass crate: https://lib.rs/crates/privacypass
- Session Protocol V2: https://getsession.org/session-protocol-v2
- Briar Wikipedia: https://en.wikipedia.org/wiki/Briar_(software)
- Briar BQP spec: https://code.briarproject.org/briar/briar-spec/-/blob/master/protocols/BQP.md
- Cwtch: https://openprivacy.ca/work/cwtch/
- Cwtch security intro: https://docs.cwtch.im/security/intro
- Cwtch risk model: https://docs.cwtch.im/security/risk
- Council CSAR position: https://www.consilium.europa.eu/en/press/press-releases/2025/11/26/child-sexual-abuse-council-reaches-position-on-law-protecting-children-from-online-abuse/
- netzpolitik, EP vote July 2026: https://netzpolitik.org/2026/eu-parlament-freiwillige-chatkontrolle-geht-mit-verfahrenstrick-durch/
- netzpolitik, second extension: https://netzpolitik.org/2026/freiwillige-chatkontrolle-ausnahmeregel-wird-zum-zweiten-mal-verlaengert/
- Chat Control July 2026 (Fortuna): https://andreafortuna.org/2026/07/10/chatcontrol-survives/
- CSAR trilogue Sept 29 (secondary): https://thecybersecguru.com/news/chat-control-2-0-september-29-trilogue/
- netzpolitik, data retention bill: https://netzpolitik.org/2026/dritter-versuch-bundesregierung-beschliesst-anlasslose-vorratsdatenspeicherung/
- Bundestag IP retention debate: https://www.bundestag.de/dokumente/textarchiv/2026/kw26-de-ip-adressen-1191866
- BfDI on messengers: https://www.bfdi.bund.de/DE/Fachthemen/Inhalte/Telemedien/Messengerdienste.html
- BNetzA notification duty: https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Unternehmenspflichten/Meldepflicht/start.html
