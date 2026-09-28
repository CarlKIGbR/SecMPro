---
title: "R4 — Serverless / peer-to-peer designs for v1.1 (research brief)"
date: 2026-09-25
status: research input (not normative; the normative documents are docs/02-architecture.md, docs/07-milestones.md and docs/08-decisions.md)
---

# SecMPro v1.1: research brief on serverless and P2P messaging (as of 2026-09-25)

Everything below was checked against live sources (project changelogs, READMEs, specs, crates.io) during this session. Anything I could not confirm is marked **UNVERIFIED**. The web-search budget ran out partway through, so the later checks were direct fetches of primary sources.

## 0. Executive summary

- **Arti onion-service hosting: the Tor Project contradicts itself.** Arti 2.6.0 came out on 2026-09-01 (`arti-client` and `tor-hsservice` 0.46.0 on 2026-09-02).
  - arti.torproject.org says: "proxy and onion service support are ready for use, but not all features of C Tor are available."
  - The README (Aug 2026) says Arti "can run and connect to onion services" and is "suitable for general client usage".
  - But `doc/OnionService.md` on `main` still says hosting is "**suitable for testing and experimentation only** … may even compromise the privacy of your other uses of the same Arti instance." Parts of that page are stale.
  - Real gaps remain: service-side PoW is still behind the experimental `hs-pow-full` feature, circuit padding machines (Padding=2) are not implemented, and `onion-service-service` is not a default feature.
  - The Rust wrapper `tor-interface` 0.6.8 (used by Gosling) calls its Arti provider "experimental [and] not fully implemented."
- **Every anonymity-first P2P messenger (Briar, Cwtch, Ricochet) uses Tor onion services.** Every design built on a DHT, libp2p, OpenDHT, Hyperswarm or iroh-direct exposes IP addresses.
- **Offline delivery is the unsolved core.** Every project ends up with a helper node: Briar Mailbox, Cwtch untrusted servers, Session swarms, Nym gateways.
- **None of the P2P anonymity messengers are post-quantum.** Tor has no PQ circuit handshake either (proposal 355 is informational only). SecMPro's PQ has to live entirely at the end-to-end layer.
- **Recommendation for v1.1:**
  - Tor onion services with per-contact endpoint addresses and restricted discovery (the Gosling pattern), with full vanguards.
  - Run it behind a `TorProvider` abstraction: bundled C tor 0.4.9.x for the production release, Arti as the target.
  - Offline delivery via an optional owner-run "mailbox" onion service, which can be the **v1 relay binary repurposed**.
  - Discovery only out-of-band. No DHT.

## 1. Existing serverless / P2P messengers

| Project | Transport / discovery | Offline delivery | Metadata exposure | PQ | Rust | Status (2026) |
|---|---|---|---|---|---|---|
| **Briar** | Bramble suite: BTP (transport security), BSP (delay-tolerant sync), BQP (QR key agreement), BRP (rendezvous), BHP (handshake). Runs over Tor onions, Bluetooth, Wi-Fi and removable media. BRP derives pseudo-random onion addresses from a shared secret, so only public keys need exchanging. | Briar Mailbox (Jun 2023): owner-run onion service on a spare Android device; only the owner and their contacts use it. Forums replicate via BSP. | BTP "does not provide anonymity" by itself; Tor supplies it. Contacts can see online status. | None | No (Java/Kotlin) | **Maintenance mode since 2026-07-09**, security fixes only. Causes named: Android battery drain, unreliable background operation, no funding. |
| **Cwtch** | Tapir over Tor v3 onions, one onion per profile, 3DH authentication with offline deniability. | "Untrusted infrastructure" servers store all group ciphertext and clients download everything ("naive PIR"). Anti-spam is only a weak PoW "spamguard". | The server sees connection patterns. The profile onion reveals online status. | None mentioned | No (Go and Flutter) | Active. 1.17 (2026-09-01) added Hybrid Groups (roles, moderation, optional *trusted* host) and bundles C tor 0.4.9.11. |
| **Ricochet-Refresh / Gosling** | One onion per user in 3.0. The 3.1-alpha is a Rust rewrite (tego-rs) moving to Gosling. | None | 2019–21 German police deanonymisation of an *old* Ricochet user via guard discovery plus netflow timing; it lacked vanguards-lite. | None (Gosling uses ed25519/x25519) | **Yes**: `gosling` 0.5.4 (2026-09-09) | 3.0.x is maintenance-only since Oct 2025 (3.0.44 on 2026-07-14). |
| **Session** | *Not serverless*: service-node swarms store messages; onion requests go through service nodes. Moved to its own "Session Network" in 2025. | Swarms | Service nodes see ciphertext and timing. | Protocol V2 (announced 2025-12-01) adds PFS (removed in 2021) and ML-KEM, but was "under design", with specs due in 2026. Rollout status **UNVERIFIED**. | Partly (libsession) | Heavily criticised for no PFS (Privacy Guides). Soatok's Jan 2025 critique is **UNVERIFIED** (fetch blocked). |
| **Berty / Wesh** | libp2p/IPFS plus OrbitDB CRDTs, BLE/mDNS, rotating time-based rendezvous points. | CRDT sync | Docs: "IPFS is not privacy-focused… any peer can resolve a peerID to its associated public IP address." README: not for sensitive data. | None | No (Go) | v2.471.14 (2026-07-03) |
| **Veilid / VeilidChat** | Rust framework: DHT, safety routes (sender-chosen) plus private routes (receiver-chosen), default one hop each. | Encrypted DHT records (encryption on by default since 0.5.0) | IPs hidden by routes, but anonymity is weaker than Tor: short routes, small network. No independent analysis found (**UNVERIFIED**). | VLD0 is classical. `VLD1` (ML-DSA/ML-KEM) key types appear in 0.5.7, but HPKE is implemented only for VLD0/NONE. | **Yes**: `veilid-core` 0.5.7 (2026-07-19), pre-1.0, wire-breaking 0.5.0 | VeilidChat 0.5.x "internal" builds only: basic groups, linked devices. |
| **Tox** | DHT plus direct UDP | None | IP visible to contacts. Handshake key-compromise-impersonation issue (#426) **open since 2017**. | None | No (C) | Legacy |
| **Jami** | OpenDHT plus ICE/TURN; each conversation ("swarm") is a git repository. | DHT used for offline notification; device-to-device sync | DHT nodes and peers see IPs; centrally run username registry. | None | No (C++) | Active (Nov 2025 releases) |
| **Delta Chat** | Email / chatmail relays (not P2P), Rust core. iroh "realtime" P2P channels for webxdc apps (Nov 2024). | Mail relays | Realtime channels can expose your IP to chat partners. "Close to zero metadata" to servers since 2.48 (Mar 2026). Multi-relay identities (FOSDEM 2026). | **UNVERIFIED** | Yes | Active |
| **Matrix P2P** | Pinecone/Dendrite stalled. Work resumed **July 2026** at Element (Dutch government funding) with "Neutrino", an embedded Rust homeserver. | — | "**not yet secure** for use in untrusted networks" | — | Yes (new) | Experimental |
| **Keet / Holepunch** | Hyperswarm/HyperDHT topics plus hole punching | Peers | IPs visible to DHT nodes and peers | **UNVERIFIED** | `hyperswarm` crate 0.1.0 (2026-06), immature | Keet's source availability **UNVERIFIED** |

**What these projects teach:**
1. Use onion services for anything that must hide IPs.
2. One long-lived public onion per user has two problems. Anyone who has the address can track the user's online status. It is also the classic guard-discovery target (the Ricochet case). Gosling's answer: one identity onion that can be switched off, plus one endpoint onion per authenticated peer.
3. Briar failed on mobile battery and background limits. A desktop-first SecMPro avoids most of that.
4. Funding and sustainability risk is real: Briar is in maintenance mode, Ricochet is crowdfunding.

**SimpleX's argument against P2P:** DHTs route through O(log N) nodes the algorithm chooses; most P2P networks have global identifiers; they are exposed to MITM without an out-of-band key exchange; and they are open to DRDoS. SimpleX instead uses per-connection unidirectional queues on recipient-chosen servers. **That queue model is the right abstraction to keep for v1.1** (section 8).

## 2. Anonymous and P2P transports

**Tor onion services (C tor).**
- Latest stable is 0.4.9.11 (2026-06-25). It fixed a rendezvous-point impersonation race (bug 41297), a reminder that E2E authentication must not rely on onion authentication.
- PoW defence: dynamic, dormant until under attack; introduced in 0.4.8 (Aug 2023).
- Vanguards-lite is built in since 0.4.7. Full vanguards needs an external add-on.
- Client authorisation (now called "restricted discovery"): unauthorised clients cannot decrypt the descriptor, so they cannot even find the introduction points.
- Performance (Tor Metrics OnionPerf, 2026-09-15..20):
  - Median onion-circuit round-trip is about 280–680 ms, depending on vantage point.
  - Median throughput is about 2.9–4.8 Mbit/s. That unit is my reading of the CSV's kbit/s values.
  - Fine for messaging, weak for bulk files.
- PQ: none. Proposal 355 (Mar 2025) is informational. Proposal 366 (Jul 2025, open) moves the onion-service handshake to ntorv3 as a step toward PQ. No timeline.

**Arti (Rust Tor): the critical question.**
- Already in place:
  - Full vanguards natively (since 1.2.2, Apr 2024; use ≥1.2.5).
  - Restricted discovery stable since 1.7.0 (2025-10-30).
  - Memory quotas (1.3.0).
  - Client-side PoW (1.3.0).
  - Congestion control and Counter Galois Onion always on in 2.6.0.
  - AF_UNIX targets (2.5.1).
  - Onion-service client bug fixes (2.4.0).
- Still missing:
  - Service-side PoW is experimental (since 1.5.0, Aug 2025; still `__is_experimental` in 2.6.0).
  - No padding machines.
  - Conflux is not used.
  - Official hosting doc still says testing only.
  - The onion-services ecosystem page calls server-side support "less mature".
- **Verdict:** fine for development and beta. For a production release marketed as "maximum security", either wait for the warning to be removed or ship C tor through the same abstraction.

**iroh (n0).**
- 1.0 on 2026-06-15, now 1.2.0 (2026-09-09). Wire compatibility is guaranteed within v1.
- Features: QUIC multipath, QUIC NAT traversal, relay fallback, custom transports (since 0.97).
- By default, address lookup **publishes your relay URL and direct IP addresses to a DNS service** under your EndpointId. Relays see EndpointIds and your IP. Peers see your IP. **So iroh does not hide IPs.**
- PQ: hybrid X25519MLKEM768 handshake, opt-in (`prefer-post-quantum`, May 2026). Authentication is still Ed25519.
- `iroh-tor-transport` (announced Jan 2026) is **experimental**. It uses the *C tor control port*, not Arti. It derives the .onion from the endpoint key, and you must manually disable all other transports and address lookup or you leak.

**rust-libp2p.**
- 0.57.0 (2026-09-11), `libp2p-kad` 0.49.0, still pre-1.0.
- DCUtR hole punching succeeds about **70% ± 7.1%**, with TCP roughly equal to QUIC (arXiv 2510.27500).
- Kademlia lookups expose the target key and your IP to the nodes on the path, and are open to Sybil and eclipse attacks. No anonymity.

**I2P.**
- Java I2P 2.11.0 (2026-02-09): "Post-Quantum crypto is now enabled at the ratchet layer by default." Current release is 2.13.0 (2026-07-20).
- Rust: `emissary-core` 0.4.0 (2026-04). It is young: NTCP2, SSU2, SAMv3, I2CP.
- Smaller anonymity set than Tor.

**Nym mixnet.**
- Loopix-style mixing plus cover traffic, so the strongest protection against a global passive adversary.
- An address is `identity.encryption@gateway`, which reveals the gateway, and "the Gateway holds your messages" (offline storage). Replies without revealing the gateway use SURBs.
- `nym-sdk` 1.21.6 (2026-09-04).
- Depends on the network's token and credential system. PQ status **UNVERIFIED**.

**Veilid.** See section 1. Promising, but not ready for a high-assurance production release.

### Transport comparison

| Candidate | IP anonymity | NAT traversal | Offline delivery | Rust maturity | PQ readiness |
|---|---|---|---|---|---|
| Tor onions via C tor (control port; `tor-interface` LegacyTorClient) | Strong (3+3 hops, guards, vanguards-lite; full via add-on) | Inherent (outbound only) | None (needs mailbox) | Mature daemon, Rust controller | None at the transport; E2E must carry PQ |
| Tor onions via Arti 2.6 | Same design, native full vanguards | Inherent | None | Native and embeddable. Hosting officially "testing only"; service PoW experimental | None |
| iroh direct | **None** (IP to peer, relay, DNS lookup) | Excellent | None | 1.x stable (Jun 2026) | Hybrid KEM opt-in; auth classical |
| iroh + Tor transport | Tor-grade *if* everything else is disabled | Via Tor | None | Experimental; C tor only | As above |
| rust-libp2p | None; DHT leaks | Good (~70% DCUtR plus relay v2) | None | Pre-1.0, widely used | Classical (**UNVERIFIED** PQ options) |
| Veilid | Moderate (short routes, small network) | Built in | DHT records | Pre-1.0 (0.5.7), wire breaks | VLD1 partial |
| I2P (emissary / i2pd via SAM) | Good, smaller set | Built in (SSU2) | None | emissary young; i2pd is C++ | PQ ratchet default (Java 2.11) |
| Nym | Strongest vs global passive adversary | Built in | Gateway storage | SDK mature-ish | **UNVERIFIED** |

## 3. Offline delivery without adding metadata

The options:
- **Online-both-sides only**, with a persistent sender outbox and retries. Zero added metadata. Workable for desktops that are often online, but it breaks when two users' online hours never overlap.
- **Owner-run mailbox onion (the Briar Mailbox model).** No third party learns the social graph. Contacts reach it over Tor; the owner polls it over Tor. On a VPS, the host sees only Tor traffic volume.
- **Untrusted shared server (the Cwtch model).** Download-everything hides group membership but scales badly, and spam is hard.
- **Store-and-forward via friends / epidemic sync (the BSP model).** Fine *within a group* whose members already know each other. For 1:1 chats it leaks the relationship to the friend.
- **DHT dead drops, including Veilid DHT records.** Lookup keys and timing leak unless every access goes through anonymous routes. Also churn, spam and storage abuse.

**Recommendation for SecMPro v1.1:**
- **Tier 0:** direct delivery over the per-contact onion, plus a durable outbox with jittered retries.
- **Tier 1 (optional, recommended):** a personal mailbox. This is the **v1 relay server rebuilt to run as an onion service** owned by the recipient (Raspberry Pi, home server or VPS), or by a trusted friend. It holds per-contact queues with padded, fixed-size ciphertext and per-contact restricted-discovery keys or capabilities.
- **Tier 2:** group members re-share group DAG messages they already hold.
- **Do not use public DHT dead drops in v1.1.**

## 4. Discovery and unlinkable addressing

- **Out-of-band invitation** (QR or link) containing:
  - protocol version;
  - hybrid identity key (Ed25519 + ML-DSA) or its fingerprint;
  - an ML-KEM-768 + X25519 prekey;
  - a **one-time invitation onion** plus its restricted-discovery x25519 key, so it is unreachable without the link;
  - a one-time token and an expiry.
- Handshake over the invitation onion. Each side then creates a **per-contact endpoint onion** for the other and issues a client-auth key and mailbox capability. Then the invitation onion is destroyed. This is Gosling's identity/endpoint split, and the P2P analogue of SimpleX's per-contact queues.
- **Rotate per-contact addresses** by epoch or in-band (Briar's BRP derives addresses from the pairwise secret) to limit long-term correlation. Removing a contact means dropping their client key and rotating.
- **Never publish in a DHT.** Kademlia lookups leak the target key and your IP.
- **Friend-of-friend introductions:** the introducer relays a signed one-time invitation over existing channels. Optionally attach a Privacy-Pass-style token (see section 6).
- An optional "public contact address" should be a separate identity onion that can be switched off, as in Gosling.

## 5. Group messaging

- **MLS (RFC 9420) needs ordered commits.** Rust options: `openmls` 0.9.0 (2026-08-25) and `mls-rs` 0.56.0. PQ ciphersuites are in `draft-ietf-mls-pq-ciphersuites-06` (2026-07-21): ML-KEM hybrids and ML-DSA.
- **Decentralised MLS** (`draft-kohbrok-mls-dmls-03`, 2025-10-20, **expired**) uses FREEK fork-resilience but admits retained keys weaken forward secrecy.
- **DCGKA** (Weidner, Kleppmann, Hugenroth, Beresford; ACM CCS 2021) needs no total order; it gives FS and PCS under concurrency. Rust implementation: `p2panda-encryption` 0.7.1 (2026-08-21), built on a causal DAG plus a CRDT membership model with "strong removal" (`p2panda-auth`). The audit by Radically Open Security was planned; its result is **UNVERIFIED**. p2panda's networking layer is built on iroh.
- **Keyhive/BeeKEM** (Ink & Switch): concurrent TreeKEM, `beekem` 0.4.0. Pre-alpha: "DO NOT use… in production."
- **Recommendation for v1.1 (small groups, up to about 50):**
  - Sender keys fanned out over the pairwise PQ channels, rekeyed on every membership change.
  - A causal message DAG, synced BSP-style so members can forward to each other.
  - An admin-signed membership log.
- **Research for v1.2:** MLS with the **group owner's device acting as sequencer**, ordering commits to replace the delivery service, or DCGKA via p2panda.

## 6. DoS and spam without a server

- **Restricted discovery on every endpoint** is the strongest control: strangers cannot reach the introduction points at all.
- **Per-contact endpoints** give per-contact rate limits and clean revocation.
- **Invitation onions:** one-time, short time-to-live, Tor PoW enabled (C tor 0.4.8+; Arti's service-side PoW is experimental).
- **Application layer:** capability tokens MAC'd with the pairwise key; per-contact quotas at the mailbox; Arti memquota.
- **Unsolicited introductions:** contacts issue Privacy Pass tokens (RFC 9576/9577/9578). A stranger redeems one without revealing which contact vouched for them.

## 7. Multi-device and identity continuity without a key-transparency server

- IETF KEYTRANS (`draft-ietf-keytrans-protocol-05`, 2026-07-06) assumes a **Service Operator**, so it does not apply to a serverless design.
- **Proposed model:**
  - A long-term hybrid identity key signs device certificates.
  - The device list is a **signed, hash-chained, versioned log**, pushed over pairwise channels.
  - Group members **gossip the log-head hashes they have seen** to detect split views.
  - Safety numbers cover the identity key; device additions and removals are announced.
  - Revocation is a signed log entry.
  - A cold recovery key signs any identity succession. Contacts flag a succession that isn't signed.
- **Device topology:** don't share onion keys between devices (duplicate descriptors conflict). Give per-contact endpoints to one "primary" device, and have the others sync through the mailbox and device-to-device channels (the Briar and Jami swarm pattern).

## 8. Recommended v1.1 architecture

**Transport**
- Choose (a): Tor onion services with per-contact endpoints, restricted discovery and full vanguards, behind a `TorProvider` trait (as in `tor-interface`).
- Production release: bundled C tor 0.4.9.x via control port, unless Arti's hosting warning has been lifted and service PoW is stable by then.
- Development and target: Arti 2.x, using `TorClient::launch_onion_service`.
- Reuse Gosling or reimplement its pattern. Gosling itself is classical and has no FS at its handshake layer; SecMPro's PQ E2E has to provide both.
- Option (b), iroh over Tor: rejected as the primary path (experimental, C tor only, IP-leak risk if misconfigured). Keep plain iroh only as an **opt-in, off-by-default** direct fast path for bulk files between mutually trusted contacts, with an explicit IP-disclosure warning (Delta Chat's model).
- Option (c), Veilid: watch for v2 (1.0, VLD1, independent anonymity analysis).
- Nym: a candidate later for mailbox access.

**Offline delivery and discovery:** as in sections 3 and 4.

**Migration abstraction.** Keep v1's relay semantics, but make them transport-neutral:
```rust
trait QueueTransport {
    async fn create_queue(&self) -> Result<(SendCap, RecvCap)>;   // v1: relay queue; v1.1: per-contact onion or mailbox queue
    async fn send(&self, to: &SendCap, env: &Envelope) -> Result<DeliveryHint>;
    fn subscribe(&self, rx: &RecvCap) -> BoxStream<'_, Result<(MsgId, Envelope)>>;
    async fn ack(&self, rx: &RecvCap, id: MsgId) -> Result<()>;
    async fn rotate(&self, rx: &RecvCap) -> Result<(SendCap, RecvCap)>;
}
```
- `SendCap` and `RecvCap` are opaque, serialisable capabilities: an onion address, client-auth key, queue ID and token, or a v1 relay URL plus queue ID.
- Each contact holds an ordered list of routes: direct onion, then mailbox, then v1 relay (for a transition period).
- **Envelope rules:**
  - padded to fixed size buckets;
  - no sender ID or routing data in clear;
  - message ID, causal parents, TTL and E2E delivery receipt all *inside* the ciphertext;
  - idempotent, so duplicates across routes are harmless.
- If v1's envelopes and queue IDs already meet these rules, v1.1 is mostly a new `QueueTransport` implementation plus the mailbox build of the relay.

## 9. Open questions and uncertainties

- When will the Tor Project drop Arti's "testing only" hosting warning and stabilise service-side PoW and padding? **UNVERIFIED / unknown.**
- Cost of scaling N per-contact onions: roughly 3 introduction circuits each, plus descriptor uploads to 8 HSDirs (my estimate from rend-spec defaults, not checked this session). Could a client hosting many onions be fingerprinted? Needs measurement. Tor guidance **UNVERIFIED**.
- Per-descriptor limit on restricted-discovery clients: my estimate is a few hundred, **UNVERIFIED**. This matters if the design falls back to one shared onion per user.
- Onion setup latency (descriptor fetch, introduction, rendezvous) and new-descriptor propagation time: not measured here, **UNVERIFIED**.
- Online status is unavoidably visible to authorised contacts. A "mailbox-only mode" hides it at a latency cost.
- Tor has no PQ, so traffic metadata and onion addresses are exposed to harvest-now-decrypt-later attacks.
- Still unconfirmed: Session V2 rollout, p2panda audit result, Veilid VLD1 activation, Keet source status, Nym PQ status.
- The v1 protocol wasn't provided for this research. The migration advice assumes queue-based relay semantics.

## Sources
- Arti: https://gitlab.torproject.org/tpo/core/arti/-/raw/main/README.md · https://gitlab.torproject.org/tpo/core/arti/-/raw/main/doc/OnionService.md · https://gitlab.torproject.org/tpo/core/arti/-/raw/main/doc/Compatibility.md · https://gitlab.torproject.org/tpo/core/arti/-/raw/main/CHANGELOG.md · https://gitlab.torproject.org/tpo/core/arti/-/raw/main/crates/arti/Cargo.toml · https://arti.torproject.org · https://blog.torproject.org/arti_2_6_0_released/ · https://blog.torproject.org/arti_2_5_1_released/ · https://blog.torproject.org/arti_2_4_0_released/ · https://blog.torproject.org/arti_1_7_0_released/ · https://blog.torproject.org/announcing-vanguards-for-arti/ · https://blog.torproject.org/arti_1_3_0_memquota/ · https://onionservices.torproject.org/dev/implementations/
- Tor: https://gitlab.torproject.org/tpo/core/tor/-/raw/main/ReleaseNotes · https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services/ · https://blog.torproject.org/tor-is-still-safe/ · https://spec.torproject.org/proposals/355-revisiting-pq.html · https://spec.torproject.org/proposals/366-ntorv3-for-hs.html · https://metrics.torproject.org/onionperf-latencies.csv · https://metrics.torproject.org/onionperf-throughput.csv · https://forum.torproject.org/t/mitigating-application-layer-denial-of-service-on-onion-services/22062
- Briar: https://briarproject.org/news/2026-maintenance-mode/ · https://briarproject.org/news/2023-briar-mailbox-released/ · https://briarproject.org/how-it-works/ · https://code.briarproject.org/briar/briar-spec/-/raw/master/protocols/BTP.md · …/BRP.md · …/BSP.md · …/BQP.md · https://code.briarproject.org/briar/briar-mailbox/-/raw/main/README.md · https://en.wikipedia.org/wiki/Briar_(software)
- Cwtch: https://docs.cwtch.im/blog/cwtch-1-17/ · https://docs.cwtch.im/security/components/cwtch/server · https://docs.cwtch.im/security/components/tapir/authentication_protocol · https://docs.cwtch.im/security/risk
- Ricochet and Gosling: https://github.com/blueprint-freespeech/ricochet-refresh/releases · https://archive.fosdem.org/2026/events/attachments/U9QZSJ-gosling-p2p-onion-services/slides/267438/fosdem-20_iwabc3c.pdf · https://gosling.technology/gosling-spec.xhtml · https://docs.rs/tor-interface/latest/tor_interface/
- Session: https://getsession.org/session-protocol-v2 · https://www.privacyguides.org/news/2025/12/03/session-messenger-adds-pfs-pqe-and-other-improvements/ · https://en.wikipedia.org/wiki/Session_(software)
- Berty: https://github.com/berty/berty · https://github.com/berty/berty/releases · https://berty.tech/docs/protocol/
- Veilid: https://gitlab.com/veilid/veilid/-/raw/main/CHANGELOG.md · https://veilid.com/how-it-works/private-routing/ · https://veilid.com/how-it-works/cryptography/ · https://gitlab.com/veilid/veilidchat/-/raw/main/CHANGELOG.md · https://en.wikipedia.org/wiki/Veilid
- Tox and Jami: https://github.com/TokTok/c-toxcore/issues/426 · https://en.wikipedia.org/wiki/Jami_(software) · https://docs.jami.net/en_US/developer/jami-concepts/swarm.html
- Delta Chat: https://delta.chat/en/blog · https://delta.chat/en/2024-11-20-webxdc-realtime · https://archive.fosdem.org/2026/schedule/event/3F9VTU-deltachat-chatmail-relays-multi-transport/
- Matrix P2P: https://arewep2pyet.com/
- Hyperswarm: https://docs.pears.com/building-blocks/hyperswarm
- SimpleX: https://simplex.chat/docs/simplex.html
- iroh: https://www.iroh.computer/blog/v1 · https://www.iroh.computer/blog · https://www.iroh.computer/blog/tor-custom-transport · https://github.com/n0-computer/iroh-tor-transport · https://www.iroh.computer/blog/iroh-post-quantum-handshakes · https://docs.rs/iroh/latest/iroh/ · https://docs.rs/crate/iroh/latest
- libp2p: https://raw.githubusercontent.com/libp2p/rust-libp2p/master/libp2p/CHANGELOG.md · https://github.com/probe-lab/dcutr-project · https://arxiv.org/abs/2510.27500
- I2P: https://i2p.net/en/blog/ · https://i2p.net/en/blog/2026/02/09/i2p-2.11.0-release/ · https://github.com/eepnet/emissary
- Nym: https://nym.com/docs/network/mixnet-mode/anonymous-replies · https://nym.com/docs/network/reference/addressing
- Group key agreement and KT: https://eprint.iacr.org/2020/1281 · https://datatracker.ietf.org/doc/draft-kohbrok-mls-dmls/ · https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/ · https://p2panda.org/2025/02/24/group-encryption.html · https://p2panda.org/ · https://www.inkandswitch.com/keyhive/notebook/ · https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/
- crates.io API (versions and dates): https://crates.io/api/v1/crates/{arti-client,tor-hsservice,iroh,libp2p,libp2p-kad,veilid-core,openmls,mls-rs,nym-sdk,emissary-core,gosling,tor-interface,p2panda-encryption,beekem,hyperswarm}
- Cited from memory, not fetched this session: Privacy Pass RFC 9576/9577/9578 (Jun 2024), MLS RFC 9420 (Jul 2023), FREEK (fork-resilient CGKA), rend-spec HSDir replica parameters.
