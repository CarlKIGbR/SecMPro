# SecMPro — Open Questions for the Owner

Decisions the implementing agent must **not** make on its own. Each has a default the plan assumes until the owner answers; the answer is then recorded as an ADR.

| Id | Question | Default assumed by the plan | Needed by |
|---|---|---|---|
| OQ-1 | Project license? (AGPL-3.0-or-later like SimpleX/Signal servers; or MIT/Apache-2.0 dual for maximum reuse; GPLv3 also compatible with Slint's dual license) | AGPL-3.0-or-later for relay and clients | M0 (license headers, deny.toml) |
| OQ-2 | Product/brand name and the URI scheme (`secmp://`)? Protocol name "SecMP" is used throughout. | SecMPro / `secmp://` | M3 (invitation format is frozen in vectors) |
| OQ-3 | Repository hosting and CI: GitHub with Actions + owner's self-hosted runner for the Windows VM, or fully self-hosted (Forgejo/Gitea + runners)? | GitHub + self-hosted Windows runner (ephemeral VM) | M0 |
| OQ-4 | Traffic budget: is ~260 MB/day per contact in Strict mode acceptable for your use, or should Balanced (~500 MB/day total, queues linkable at the relay) be the default? | Strict default, Balanced offered | M6 / ADR-018 |
| OQ-5 | Relay access: shared `relay_access_key` for v1 (operator hands it to invited users) is acceptable until M13 tokens? | Yes | M5 |
| OQ-6 | Direct (non-Tor) TLS listener enabled on the production relay? It exposes client IPs to the host and Hetzner. | Disabled in production; enabled on the test relay | M10 |
| OQ-7 | Accessibility: is "message content hidden from screen readers unless Accessibility mode is on" acceptable, and can a screen-reader user review it before 1.0? | Yes; review requested | M9 |
| OQ-8 | Windows code signing: Azure Artifact Signing (managed HSM, subscription) vs. an OV certificate on a hardware token? | Azure Artifact Signing | M11 |
| OQ-9 | External audit budget/timing (Trail of Bits / Cure53 / ROS via OTF Security Lab or Sovereign Tech Agency)? Design review after M4, implementation audit after M11? | Apply to OTF/STA after M4; implementation audit before 1.0 | M4, M11 |
| OQ-10 | Message retention default on clients (forever vs. 7 days) and default delivery receipts (on for verified contacts)? | Forever locally (user-settable), receipts on for verified contacts, read receipts off | M7 |
| OQ-11 | Should v1 include inline attachments up to 64 KiB (fragments) or defer all attachments to the blob channel (M15)? | Inline ≤ 64 KiB in v1 | M7 |
| OQ-12 | Hetzner host: dedicated AX (EPYC) or cloud instance for the v1 relay? Do you want SME/TSME and Secure Boot checked via KVM console? | Existing owner server for test; decision for production at M10 | M10 |
| OQ-13 | Deniability: is offline deniability a hard requirement (it constrains future PQ authentication choices)? | Yes (keep X3DH-style deniability) | ADR-021 review |
| OQ-14 | BSI TR-02102 conformance as a goal (would add P-256/P-384 + CatKDF variants and remove X25519 from the "recommended" path)? | Not a v1 goal | Before v2 |
| OQ-15 | Arti vs bundled C tor in the v1.1 *client* for hosting endpoints (production release)? | C tor bundled for release, Arti in development, behind `TorProvider` | M16 |
| OQ-16 | Tor proof-of-work: accept Arti's experimental `hs-pow-full` feature (LGPL dependencies) in the client so the relay can enable PoW defence, or keep PoW off until Arti stabilises it (weaker DoS resistance)? | PoW off in v1 (ADR-024) | M6 / M10 |
| OQ-17 | Reference implementation (`ref/`, Python) is written by a *separate* agent session from the spec alone — who runs that session (owner starts it, reviewer supplies the brief)? | **Decided 2026-09-28:** reviewer prepared `docs/prompts/kickoff-ref.md`; owner starts the session during M1 | M1 |
| OQ-18 | Repository visibility: GitHub's free plan offers no branch protection for private repositories, so "PR-only `main`" is a process rule. Make the repository **public now** (reviewer's recommendation: AGPL project, unlimited Actions minutes, branch protection, private vulnerability reporting, Dependabot alerts; README banner "pre-release — do not use"), or upgrade to GitHub Pro and stay private until 1.0? | Public | Before M1 merge, at the latest M2 |
