# SecMPro — Vision and Scope

Status: baseline (2026-09-25). Owner: Christopher Carl. Architect/reviewer: Fable. Implementer: Claude Code (Opus).

## 1. What we are building

A messenger for people who assume that every server, every network and every operating system between them is hostile. SecMPro has:

- **Its own protocol (SecMP/1)** built from public, formally analysed designs (PQXDH, Double Ratchet with header encryption, Noise-style link handshakes) and post-quantum hybrids everywhere a key is agreed.
- **Zero trust in infrastructure.** The relay stores fixed-size ciphertext in RAM and executes eight commands. It cannot identify anyone, cannot see who talks to whom, cannot see when someone sends or receives (only when a client is online), and cannot produce logs because it has nothing to log.
- **No identifiers.** No phone numbers, usernames, accounts, or directories. Contacts are made with an invitation exchanged out of band and confirmed with a safety number.
- **No metadata by design.** Fixed cells, constant-rate cover traffic, anonymous per-queue capabilities, Tor by default.
- **Screen-capture resistance** as a first-class feature on Windows and Linux, with an honest statement of what is prevented, what is mitigated, and what no software can prevent.
- **Security by construction:** memory-safe Rust, typed crypto APIs, a single ciphersuite, formal models, external test vectors, fuzzing, mutation testing, reproducible signed builds, vetted dependencies.

## 2. Versions and definitions of done

| Version | Definition of done |
|---|---|
| **v1** | One relay (Linux, Hetzner) and two desktop clients (one Linux, one Windows) communicate with **all** security functions active: PQ hybrid handshake and ratchet, invitation + safety-number flow, fixed cells at constant rate over Tor, encrypted local store, screen-capture protection, hardened no-log relay, reproducible signed builds, formal models and gates green. Acceptance protocol: `07-milestones.md` M12. |
| **v1.1** | Peer-to-peer, serverless operation: clients reach each other over per-contact Tor onion endpoints; an optional personal mailbox (the relay binary run by the user) covers offline delivery; the v1 relay is no longer required. Acceptance: M20. |
| v1.x | Hardening increments that do not change the protocol's security model: anonymous tokens, process split/sandbox, attachments channel, TUF updates. |
| v1.2+ | Small groups, multi-device, PQ-deniable authentication, mobile. Not designed in detail yet. |

## 3. Guiding principles (in priority order)

1. **Security and privacy over features.** A feature that cannot be built without weakening a property in `01-threat-model.md` is not built.
2. **Fail closed, never degrade silently.** Every failure path ends in "content hidden / message dropped / user warned", never in "try without X".
3. **No cleverness in cryptography.** Compose audited primitives exactly as specified; every construction has a spec paragraph, test vectors and a model.
4. **Honesty in claims.** The UI and docs say precisely what the relay can see and which screen-capture vectors are not preventable.
5. **Small, boring, inspectable.** Few dependencies, few commands, few modes. Every deviation is an ADR.
6. **Reviewability.** Every milestone produces evidence a stranger could check: test names, vectors, hashes, model outputs.

## 4. Non-goals (all versions currently planned)

- Interoperability with other messengers or protocols.
- Federation between relays (relays are independent; users pick any).
- Discovery of contacts by anything other than an invitation.
- "Delete for everyone" guarantees (view-once and expiry are best-effort on the receiver's device).
- Prevention of capture by a compromised OS kernel/admin or by a camera.

## 5. Who does what

| Role | Responsibility |
|---|---|
| Owner (Christopher) | Decides open questions (`09-open-questions.md`), operates the relay, runs the Windows VM for tests, approves releases. |
| Architect / reviewer (Fable) | Owns `docs/00–09`; reviews every milestone against the review checklist; approves ADRs; runs adversarial reviews at M11. |
| Implementer (Claude Code / Opus) | Builds milestones sequentially per `07-milestones.md` following `CLAUDE.md`; writes milestone reports; proposes ADRs; never changes the threat model or spec unilaterally. |
| External auditors (later) | Design review after M4, implementation audit after M11. |

## 6. Document map

| File | Purpose |
|---|---|
| `CLAUDE.md` | Working rules for the implementing agent (read first) |
| `docs/00-vision-and-scope.md` | This document |
| `docs/01-threat-model.md` | Adversaries, what they can/cannot learn, screen-capture achievability, residual risks |
| `docs/02-architecture.md` | Components, crates, data flows, technology decisions |
| `docs/03-protocol-spec.md` | Normative SecMP/1 specification |
| `docs/04-client-security.md` | CS-* requirements for the desktop client and their tests |
| `docs/05-relay-ops.md` | Relay hardening, deployment, runbook |
| `docs/06-engineering-standards.md` | Rust rules, tests, CI, supply chain, Definition of Done |
| `docs/07-milestones.md` | Sequential milestone plan v1 → v1.1 with acceptance criteria |
| `docs/08-decisions.md` | ADR log |
| `docs/09-open-questions.md` | Decisions reserved for the owner |
| `docs/research/R1–R5` | Research briefs with sources (input, not normative) |
| `docs/templates/` | Milestone report and review checklist templates |
| `docs/reviews/` | Recorded reviews and acceptance evidence (created during implementation) |
