# Plan review — 2026-09-25 (adversarial review of the planning package, before M0)

Reviewer: independent review agent (Opus), commissioned by the architect (Fable). Scope: `CLAUDE.md`, `docs/00–09`. Method: line-by-line read of the spec, cross-checks against crates.io / RustSec / Arti / systemd / SQLCipher sources.

Result before fixes: 6 blockers, 20 majors, 21 minors, 5 nits. Verdict: *not ready*. All blockers and majors were resolved in **revision 2** of the documents (same day); dispositions below. The revised package is the baseline for M0.

## Blockers

| # | Finding | Disposition (rev. 2) |
|---|---|---|
| B1 | Losing the first cell of a chain permanently killed the session (KEM material only in the first message; eviction makes this routine) | **Fixed.** Every message carries its chain's `ek_pq`/`ct_pq`; one header length; step on whichever message arrives first (spec §7, ADR-004). Vector "dropped first-message-of-chain" required (App. C). |
| B2 | Chains outgrow `MAX_SKIP` (8 640 dummies/day); returning client deadlocks | **Fixed.** `MAX_FF = 2^20` fast-forward, `SKIP_WINDOW = 256` bounded storage (§7.4, ADR-011). Vector with 10 000-message gap required. |
| B3 | Header-key schedule wrong/ambiguous | **Fixed.** §7.2–7.4 rewritten to follow the Double Ratchet HE variant exactly (`(RK‖HK_A‖NHK_B)` from SK; rotation in `DHRatchet`; step detected by `nhk_r`). |
| B4 | `LinkDataV1` did not fit 8 192 B; blob overhead wrong | **Fixed.** Pad to 12 288; blob 12 360 B; 3 frames (§5.4, D.3). |
| B5 | A relay restart destroyed every session (single relay) | **Fixed.** Deterministic, re-creatable queue ids derived from keys; idempotent signed `QUEUE_NEW`; recovery procedure (§9.1, §10.4, ADR-025). M5/M12 acceptance updated. |
| B6 | Wire layouts missing (M2 impossible without invention) | **Fixed.** Appendix D with every opcode, field order, signature message, multi-frame continuation, content bodies. |

## Majors

| # | Finding | Disposition |
|---|---|---|
| M1 | HandshakeInit chunking ambiguous, shared nonce prefix visible, fragile to garbage cells, crash-resend nonce reuse | **Fixed.** Random per-cell nonces, chunk ids inside the ciphertext, persist-and-resend byte-identical, responder ignores unopenable cells (§6.5, ADR-010). |
| M2 | Initiator identity had no forward secrecy; `reply_route` unbound | **Fixed.** Inner layer under `K_id = HKDF(link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk)`; reply route lives inside `first_msg` (§6.4–6.5). |
| M3 | FETCH ack semantics undefined; no persist-before-ack | **Fixed.** Cumulative ack, idempotent FETCH, dedup by `cell_id`, persist-before-ack (§9.3, §7.5). |
| M4 | Backups roll back the ratchet | **Fixed.** CS-3.5: no ratchet/prekey/outbox state in backups; re-invite after restore. |
| M5 | Relay could tag clients via per-client `RelayInfo` keys (cached 60 days) | **Fixed.** `RelayInfo` per HELLO, never cached (§8.2, ADR-028). |
| M6 | Operator could hand out per-user access keys | **Fixed.** `akc` commitment in signed `RelayInfo` and pinned in `RelayRef` (§5.3, §9.6, ADR-028). |
| M7 | Strict-mode unlinkability overclaimed (lifecycle correlation) | **Fixed/re-scoped.** §10.6 mitigations (random phases/lifetimes, delayed one-shot control links, queue pool, rotation overlap); threat model §3.1 reworded ("not cryptographically; statistically over time"); RR-11 added. |
| M8 | Emission timing depended on cell content (persistence in the tick) | **Fixed.** Pre-built frames; tick writes bytes only; numeric tolerance in the activity-independence test (§10.1, §10.3, M6). |
| M9 | Balanced/Low-bw recipients could not drain Strict senders (livelock) | **Fixed.** Recipient-chosen periods with a drain bound; `FETCH_MULTI` with `F_M = 8` (§10.2, ADR-009). |
| M10 | Linux "Prevented" overclaimed (KDE 6.6 vs 6.7, settings clearable by same-user malware, niri built-in screenshot, wlroots screencopy) | **Fixed.** Threat model §4 and product wording rewritten; CS-1.10 verify-every-2 s + lock-on-loss; KDE ≥ 6.7. |
| M11 | GNOME/unknown compositors failed open | **Fixed.** Locked mode by default everywhere without verified exclusion (CS-1.9/1.10). |
| M12 | Two different values named `link_id` | **Fixed.** `ld_id` (link data) vs `sess_id` (link session). |
| M13 | "Only secmp-crypto imports crypto" impossible (rustls, Arti, SQLCipher) | **Fixed.** Exemptions stated (06 §3, CLAUDE.md §1.6); SQLCipher Windows spike in M0; fallback ADR-027. |
| M14 | Workspace lint config would fail (`forbid` not relaxable; group priority) | **Fixed.** `deny` + per-crate `forbid`, `priority = -1` (06 §2). |
| M15 | Dependency policy infeasible for transitive deps; AI as auditor | **Fixed.** Direct deps only; tracked exemptions; zero-exemption only for crypto/proto closure; human auditors (06 §3). |
| M16 | M3 depended on M4 (`first_msg` needs TR) | **Fixed.** Reordered: M3 = TR, M4 = HX/INV. |
| M17 | M6 depended on M7 (CLI) | **Fixed.** `secmp-testkit` `two-clients` binary in M6. |
| M18 | M12 did not prove "all security functions" (restart step impossible; eyeballed captures) | **Fixed.** New protocol: relay restart recovery, 2 h offline, fail-closed checks, PQ counters, KS test on scheduler logs, byte-count check, store forensics, Balanced mode. |
| M19 | Vectors and models circular | **Fixed.** Independent Python `ref/` (ADR-026); `formal/CLAIMS.md` fixed by the reviewer incl. expected-false queries; ProVerif mandatory. |
| M20 | Arti version naming; PoW client experimental/LGPL contradicts license policy | **Fixed.** Arti 2.6.0 / `arti-client` 0.46.x; PoW off in v1 (ADR-024, OQ-16). |

## Minors (all addressed unless marked)

COM key reuse → UtC-style `CAEAD` (§3.4). Combiner variants labelled; HybridKEM-768 now used in the link's ephemeral stage; raw-mixing rationale stated (§3.2). Type/trial gaps removed by the single header length; key-commitment claim limited to bodies (§11.1). Link handshake: version/kid in `h0`, labels in App. A, `kid` in HS1, `mac1` not a DoS defence (§8.3). OPK mandatory; invitation kinds clarified; SPK retention rule (§5.2, §6.1, §6.3). SAS iteration defined (§6.7). Consistency rule reworded (§4.1). Fragment limit 64 and M12 "60 KB inline attachment" (§7.6, M12). Owner-status `LINK_GET` (§9.4). Missing adversaries ADV-U, ADV-RG and RR-11–14 added; RR-5 re-rated; §6.6 citation fixed. CS-1.6 OWNER RIGHTS ACE; CS-1.11 wording. `secmp-sys` split into `-mem`/`-desktop`. Incremental ratchet persistence; session actor (02 §4.2). Bandwidth/capacity numbers corrected with Tor overhead (§10.2, 05 §8). systemd unit corrected (no `PrivateUsers`, `IPAddressDeny`, `AF_UNIX`, `RuntimeDirectory`). Owner-operated gates marked ⚙; mutation rule aligned; KDE 6.7; M8 spike scope. CLAUDE.md wording, `ci-fast`/`ci-full`, stop conditions, sanctioned `#[allow]` list, `ops-check`, vector generation. SQLCipher version check via `PRAGMA cipher_version`. HashMap rule corrected. "Nine commands" → eight. `QueueTransport::fetch` comment. `relay_fp` label. deny.toml license listing.

**Not changed (accepted as documented):** the anonymity set of two in v1 (inherent); classical authentication (ADR-021); relay visibility of online periods and control operations (§11.3).

## Verification pass on revision 2 (same day, second independent agent)

Arithmetic of every byte count, the ratchet walk-through (header-key alignment, KEM key placement, KDF order, skipped-key handling), the handshake data availability, the link handshake and Appendix A completeness were confirmed. New findings, all folded into **revision 2.1**:

| Sev | Finding | Disposition |
|---|---|---|
| blocker | Stale `committed_ack` after a relay restart would delete every new cell (`cell_id` restarts at 1) | **Fixed.** Reset ack/dedup on re-creation; sender discards its cell-id map; relay rejects `ack ≥ next_cell_id` (§9.1). |
| major | Balanced/Low-bw senders ignored `P_q` (reopened the drain livelock) | **Fixed.** Senders respect `P_q` in every mode; idle slots carry `PING` (§10.2). |
| major | `SKIP_WINDOW` unsound while one chain feeds two queues (rotation overlap, invitation retirement) | **Fixed.** Sender re-sends recent real messages on the new route; recipient deletes the old queue only after an empty fetch (§10.6 rule 4). |
| major | `FETCH`/`FETCH_MULTI` had no error framing | **Fixed.** `CELLR.present ∈ {0,1,2,3,4}` (§9.3, D.2). |
| major | Invitation queue deleted immediately (§6.6) vs retired with overlap (§10.6) | **Fixed.** Retire with overlap (§6.6 step 4). |
| major | Real cells sent before the handshake cells could be lost silently | **Fixed.** Only dummies on the invitation queue until R's first message decrypts (§6.5). |
| major | Invitation queue period never communicated | **Fixed.** `inv_period_s` in `InvitationV1` (241 B). |
| major | Store schema cached `RelayInfo` (contradicting §8.2) | **Fixed.** 02 §4.2. |
| minor | `last_ct_r`/`sb` undeclared or unset; skip guards; eviction order; `cmd_seq`/`CONT` wording; canonical `OK_SEND`/`CELLR`; ack timing; `arrival` counter; multi-relay Balanced; overlap accounting; reconnect rule reference; link-data re-put after restart; prekey check wording; ADR-018 title; HELLO order; `MAX_MSG_BYTES` 65535; fast-forward cost wording; naming nits | All fixed. |

## Follow-ups carried into the plan

- M0: SQLCipher/aws-lc-rs cross-build spikes (ADR-027 decision).
- M1–M5: `ref/` reference implementation in a separate session (OQ-17).
- M3/M4: reviewer fixes `formal/CLAIMS.md` before modelling.
- M6: finalise `PERIODS`/`T_*`/`F`/`F_M` (ADR-018) with measurements incl. 24 h offline drain.
- M10: DoS residual risk without PoW recorded in the threat model.
- Re-assess RR-11 at 100+ users.
