# Milestone report — M6 Transport providers, constant-rate scheduler, measurements

Branch: `m06-transport` · Base: `6300b653d0f1f176b7a31470910d5214fa87b9cc` · Author: Claude Code · Date: 2026-10-09 …
Phase A: `modell=claude-sonnet-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M06-planning/` (`BRIEF_M6.md`, `TEST-SPEC-M6.md` (177 rows: A 103, B 44, C 30), `OPEN-M6.md`,
`OPEN-M6-decided.md`, `ADR-051-proposed.md`). ADR-051 is appended to `docs/08-decisions.md` as **Proposed**; Part 2 (owner)
is not approved, so Phase A adds no third-party crate and no [DEP] row is built. Phases: A (Sonnet) → B (Opus, after the
owner's ADR-051 Part 2 approval) → C (Sonnet).

Phase A rows (103): AD-01…AD-06, S-01…S-32, CO-01…CO-08, QP-01…QP-05, OB-01…OB-08, LR-01…LR-06, AI-01…AI-06, AI-08,
AI-09, MR-01, MR-02, G-01…G-11, K-01…K-07, P-01…P-04, P-06, P-07, FZ-01, FZ-04, X-05, X-09.

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 1 | A | Commit 1: planning files, ADR-051 (Proposed), this plan, `docs/07` §M6 status line | — | done |
| 2 | A | Allowlist gate (workspace-only) and the M5 follow-ups: G-04 first, then G-01…G-11 | G-01…G-11, K-07 | open |
| 3 | A | `secmp-client-core::clock` (`Clock`, `SystemClock`, `ManualClock`), `TimingRng`, uniform draws | K-04, P-04 (part) | open |
| 4 | A | `secmp-transport::Session::{prepare, write_prepared, read_response}` (sync), pipelined responses, `ConnectOutcome` | AD-01…AD-06, FZ-01 | open |
| 5 | A | `scheduler::core`: LinkTask, modes, periods, phases, lifetimes, in-flight bound, prepare/tick split, FETCH lead, overrun | S-01…S-32, K-01…K-03, K-05, K-06, X-09 | open |
| 6 | A | Back-off and rotation/reconnect | LR-01…LR-06 | open |
| 7 | A | `outbox` (`Outbox`/`Persist`, `MemOutbox`/`MemPersist`) | OB-01…OB-08, P-03, P-07 | open |
| 8 | A | `pool` (`QueuePool`) and `control` (`ControlOps`) | QP-01…QP-05, CO-01…CO-08, P-06 | open |
| 9 | A | `secmp-testkit::VirtualDriver`; activity independence, measurements | AI-01…AI-06, AI-08, AI-09, P-01, P-02, MR-01, MR-02 | open |
| 10 | A | Kani, fuzz, xtask lists, `ci-fast`, `ci-full`, evidence under `M06-evidence/` | K-01…K-07, FZ-01, FZ-04, X-05 | open |

## 2. What was built

(to be filled during Phase A)

## 3. Evidence per acceptance criterion

(to be filled)

## 5. Deviations from spec / plan

None so far.

## 8. Blocked / questions for the reviewer or owner

None so far.
