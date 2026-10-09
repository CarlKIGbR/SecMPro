# OPEN-M5 — decisions (reviewer, engineering delegation 30.09.2026; 2026-10-03)

Source of the questions and readings: `OPEN-M5.md`. Owner-class items keep the planner's default and go into the owner
memo with a **+24 h default**; they are docs/03 text in ADR-048 (o), (p), (q) and their rows land after ratification.
"Rows" = the TEST-SPEC-M5 rows marked [O-n] (OPEN-M5-13 governs the [R5-n] rows).

| ID | Decision | Reason (one line) | Class | Rows |
|---|---|---|---|---|
| OPEN-M5-01 | **A** — no `akc` check without an access key; B offered as optional ADR-048 (q) | literal §8.2 `:539`; B widens §11.1 Q detectability to key-less invitees and is the owner's call | owner — **default, owner memo +24 h** | C-12 |
| OPEN-M5-02 | **A** — over-rate request not executed, exactly one ERR 7 frame, `cmd_seq` recorded; for LINK_PUT after its third frame (as SQ-26 A); over-limit HELLO closed before RELAYINFO. Values (engineering): per-link bucket burst 8 request frames, refill 1/s; HELLO bucket per listener burst 16, refill 4/s; HELLO→HS1 timeout 30 s; limits are config, off in the vector replay, scenario rate in the harness | uses the existing ERR 7 code; one answer shape for "not executed" (stale `cmd_seq`, rate); honest §10 schedules never reach the limits | owner (shape: ADR-048 (p)) — **default, owner memo +24 h**; engineering (values) | RL-13, RL-14, RL-22 (RL-23 reads the values) |
| OPEN-M5-03 | **A** — client-only, per direction; `NewLinkRequired` after counter 2^20 − 1; relay does not check | a compliant client cannot observe B; `LINK_LIFETIME` ≤ 24 h binds first | engineering | F-09, K-03 |
| OPEN-M5-04 | **A** — the reference's check order (QUEUE_NEW token, signature, known `recv_pk`, budget; SEND `sid`, signature; FETCH/entry `rid`, signature, `ack`; QUEUE_DEL `rid`, signature; LINK_PUT token, signature, [(o) range], `ld_id`; owner status entry and signature together) | Rust = ref for every double fault; no oracle difference | engineering | Q-07, Q-55 |
| OPEN-M5-05 | **B** — expired iff now_bucket > b + T (T = 168 h cells, 720 h idle from `last_fetch_bucket`, else `created_bucket`); link data valid through `expires_bucket` | a TTL is a delivery promise, never shortened by bucket rounding | engineering | RL-04, RL-05, RL-06, H-05 |
| OPEN-M5-06 | **B** — `expires_bucket` ∉ [now_bucket, now_bucket + 720] ⇒ ERR 6 after the third frame, nothing stored | no silent change of a client value; same class as §9.1's stale-ack MALFORMED | owner (ADR-048 (o)) — **default, owner memo +24 h** | RL-07 |
| OPEN-M5-07 | **A** — two byte pools with worst-case reservations (queue: 128 × 4096 B + overhead at QUEUE_NEW; link data: 12360 B + overhead at LINK_PUT; released on delete, consume — marker keeps its overhead — and expiry); vector config: queue pool = 2 reservations, link-data pool unlimited | bounds RAM without SEND ever failing (§9.7 (4)); reproduces OPEN-12 | engineering | Q-12, Q-33, RL-08, H-06 |
| OPEN-M5-08 | **A** — events: startup, key load, own listener bound, config error, shutdown/drain start/exit; aggregate counters only if enabled; nothing per request at any level (`expect::RELAY_TRACE_ALLOW`) | §9.7 (2) allows exactly aggregate counters | engineering | RL-03 |
| OPEN-M5-09 | **A** — drain: listener refuses new connections; QUEUE_NEW and LINK_PUT ⇒ ERR 2; everything else served; exit after `drain_secs` (60) | no new wire value; ERR_FULL already means "no new state" | engineering | RL-15 |
| OPEN-M5-10 | **A** — RELAYINFO announces the newest kid; HS1 accepted for any held kid with `valid_until ≥ now`; a kid is dropped after its `valid_until`; `rotate-static` adds kid + 1 with `valid_until` ≤ now + 5 184 000 | overlapping validity per §8.2 `:539`; stays within OPEN-4 | engineering | RL-17 |
| OPEN-M5-11 | **A** — any authenticated response that does not fit its request (op, count, position, `cmd_seq` echo, ids ≠ own derivation; ERR 6/7 single frames excepted) is a LINK-level `Rejected`, link closed | fail closed (§1.1 goal 6) | engineering | T-09 |
| OPEN-M5-12 | **A** — ADR-047 Amendment 3 (text below) | relay security kernel; Am. 2 floor applies unchanged | engineering | X-02 |
| OPEN-M5-13 | **Confirm** REF-M5 readings 2–10 as binding for Rust (reading 1 = OPEN-M5-04) | 5 and 6 are wire-visible but follow §9.4 and enter ADR-048 (k); the rest are internal or informative | engineering | Q-36, Q-44, Q-46, Q-56, F-08, RL-05, RL-20 |
| OPEN-M5-14 | **B with draw-and-discard (PR-7)** — the invite case still draws the former 16-B `inv_sid` value and discards it, so every later draw keeps its bytes; `invq_recv_seed` 32 and `owner_seed` 32 are appended after the case's last draw; `inv_sid` is derived | smallest byte delta: only `inv_sid`, the InvitationV1/URI and the two new outputs change | engineering (vector schema) | V-23, V-24, V-25, G-04, G-05 |
| OPEN-M5-15 | **A** — the retained-SPK request is "WEISUNG_REF item RF-1" (no SQ number) | the ref's SQ-28 is the FETCH_MULTI question | engineering | V-24 |
| OPEN-M5-16 | **A** — `formal/link.pvl` + `formal/link/<session>.pv`, ≤ 30 min per file, gate per (file, ID, query text) | O-18: joint files grow superlinearly | engineering | PV-01, X-04, X-05 |
| OPEN-M5-17 | **Decided** — X-07 classes "no 0x80 in the tail" and "0x80 as the last byte" (planner default, confirmed 2026-10-03) | R-93 names no classes; the two classes cover the unpad decision's branch | engineering | X-07 |

**Clarification 2026-10-09 (M05 review R-119), OPEN-M5-09:** OPEN-M5-09 A, clarified: drain answers `ERR 2` to a `QUEUE_NEW`/`LINK_PUT` that would create state; an identical `QUEUE_NEW` (same keys, existing queue) answers `OK_QUEUE_NEW` without side effects, also during drain, as at the budget limit (Q-07, OPEN-M5-04 order); the token is checked first. `LINK_PUT` ⇒ `ERR 2` is unchanged. Test: RL-15 assertion (M05 review C-10).

## ADR-047 Amendment 3 (OPEN-M5-12) — text to append after ADR-047 Amendment 2 in `docs/08-decisions.md`

**ADR-047 Amendment 3 — `secmp-relay` in the mutation gate. Status: Accepted (Reviewer, Owner-Delegation 30.09.2026) —
2026-10-03. Context: M5 adds the relay security kernel (executor, `QueueStore`, `LinkDataStore`, link server);
`docs/06` §4 names only `secmp-crypto` and `secmp-proto` for mutation testing. Decision: the mutation gate runs over
`secmp-crypto`, `secmp-proto` and `secmp-relay` in the 8 shards of Amendment 1 with the per-package rule of Amendment 2
(caught share ≥ 50 % of all generated mutants per package, unviable > 35 % a WARNING, an unaccepted survivor a failure
naming its package; every shard and package reported before a FAIL); `docs/mutants-accepted.md` rows carry `:line`.
Phase B measures the CI time per shard and reports it; the shard count changes only by a further amendment.
Consequences: `docs/06` §4 "Mutation" reads "`secmp-crypto`, `secmp-proto`, `secmp-relay`"; test
`mutants_scope_includes_relay`.**

Owner memo delivered 2026-10-03 20:40 UTC (push); defaults for OPEN-M5-01/-02/-06 and ADR-048 apply from 2026-10-04 20:45 UTC unless the owner decides otherwise.
