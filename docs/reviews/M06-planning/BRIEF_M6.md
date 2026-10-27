# BRIEF M6 — transport providers, constant-rate scheduler, measurements (Phase A)

Date: 2026-10-09 19:50 UTC (re-issued after the material-path finding; first attempt 19:20 UTC stopped without changes, branch `m06-transport` may already exist — `git checkout m06-transport` then, no second branch) · Reviewer: Fable · Executor: container `secmp-main` on carlgpu4 (first container brief) · Base: `main` = `6300b653d0f1f176b7a31470910d5214fa87b9cc` (M5 merged) · Branch: `m06-transport` · Phases and models (autonome-steuerung rule 9; full model ids, `.fortsetzung` always before `.modell-`):
**A** `BRIEF_M6.modell-claude-sonnet-5-5.md` (this conversation) · **B** `BRIEF_M6-B.modell-claude-opus-5-5.md` (new conversation after Phase A's closing push **and** the owner's ADR-051 Part 2 approval) · **C** `BRIEF_M6-C.modell-claude-sonnet-5-5.md` (new conversation after Phase B's closing push) · instructions `WEISUNG_M6-k.fortsetzung.modell-<id>.md`; every report carries `modell=<id>`.

## 0 · How this milestone is run
You implement; the reviewer plans, judges and reviews. The tests are **dictated** in `docs/reviews/M06-planning/TEST-SPEC-M6.md` (177 rows: A 103, B 44, C 30): implement every row of your phase under its exact name; helpers are allowed; every extra test is named in the report; no row is dropped and no expectation changed — a row that contradicts the spec is a STOP with the row id and the spec line. Rows marked [O-n] use the OPEN-M6-n decision in `OPEN-M6-decided.md` (= the planner default A for every row); rows marked [DEP] wait for ADR-051 Part 2; ⚙ rows follow the non-availability path of TEST-SPEC "Conventions". Reports carry numbers, run IDs, SHAs and verdict lines, never an assessment of your own work and never a proposal. No agent worktrees.

## 1 · Order = reference
`docs/07-milestones.md` §M6 (deliverables, acceptance, review focus), `CLAUDE.md`, DoD `docs/06` §8, guard rails `docs/06` §9; spec `docs/03` §10 (all of it), §9.1, §9.3, §9.5, §8.4, §12; `docs/02` §4.4. The spec is not repeated here. M7 is out of scope (store, `Sessions`, `RouteUpdate`, rotation overlap, CLI — OPEN-M6-19).

## 2 · Container rules (this run)
Do not push. End each phase with the return block giving the branch head SHA; the reviewer pushes via the gate (`sp.sh push`). Commit on branch m06-transport from main 6300b653d0f1f176b7a31470910d5214fa87b9cc.
Allowed: `sleep`, `timeout`, `tee`; long gates in the foreground. Not allowed: `taskset`, reading `/proc`, `cp -r`, `docker`, `ssh`, `rsync`; `gh` read-only. No network in any test except the loopback integration tests named in TEST-SPEC (`docs/06:95`).

## 3 · Binding planning artefacts (commit 1)
The planning artefacts are mirrored by the postbote into `target/fable/material/M6/` (inside the repo, gitignored): `mkdir -p docs/reviews/M06-planning && cp target/fable/material/M6/TEST-SPEC-M6.md target/fable/material/M6/OPEN-M6.md target/fable/material/M6/OPEN-M6-decided.md target/fable/material/M6/ADR-051-proposed.md target/fable/material/M6/BRIEF_M6.md docs/reviews/M06-planning/` (unchanged). If `target/fable/material/M6/` is missing: STOP with `ls target/fable` in the report — do not search elsewhere. `OPEN-M6-decided.md` is binding for every [O-n] row (reviewer decisions 2026-10-09; owner items keep their defaults from 2026-10-10 19:45 UTC). Append ADR-051 to `docs/08-decisions.md` as **Proposed**. Write `docs/reviews/M06-report.md` §1 (plan: phases A–C, which rows each step closes) and the `docs/07` §M6 status line. Code only after this commit.

## 4 · Conditions from the M5 review (`docs/reviews/M05-review.md` §H, verbatim index) — each is a deliverable
"**M6:** F-4 (R-122), F-5 (R-123), F-6 (R-124), F-7 (R-126), F-8 (R-127), F-10 (R-131, R-132, R-133), F-11 (R-134, R-135), F-15 (R-148); register follow-ups R-144, R-155; M6 client backoff with jitter (F-1)." plus C-3 "M6 adjusts" and VD-M5-FIX (convo.rs mutants).
Mapping: F-1 → AD-06, LR-03 (A), SIM-09 (C) · F-4 → G-01, K-07 · F-5 → G-02 · F-6 → G-03 · F-7 → G-04 (**before** any dependency of ADR-051) · F-8 → G-05 · F-10 → G-06 · F-11 → G-07 · F-15 → G-08 · R-144 → G-09 · R-155 → G-10 · convo.rs → G-11 (all A) · C-3 → G-12 (B).

## 5 · Phase split and handover
- **A (Sonnet — dictated rows, virtual clock and the M5 harness are the oracle; no new third-party crate):** `secmp-client-core` `clock`, `scheduler::core` (LinkTask, modes, periods, phases, lifetimes, in-flight bound, prepare/tick split, FETCH lead, overrun), `control` (ControlOps), `pool` (QueuePool), `outbox` (`Outbox`/`Persist` traits, `MemOutbox`/`MemPersist`), back-off; `secmp-transport` `Session::prepare`/`write_prepared`/pipelined responses (sync); `secmp-testkit` `VirtualDriver`; the F-M6 rows. Rows AD-01…AD-06, S-*, CO-*, QP-*, OB-*, LR-*, AI-01…AI-06, AI-08, AI-09, MR-01, MR-02, G-01…G-11, K-01…K-07, P-01…P-04, P-06, P-07, FZ-01, FZ-04, X-05, X-09. Handover A→B: a push whose PR run is green on `linux-fast`, `windows-native`, `xwin-cross` and `linux-full` (Kani, fuzz, mutants on the existing scope); report §1 "Phase A closed @ <sha>".
- **B (Opus — Arti/TLS integration and the async driver have no oracle):** ADR-051 Part 2 lands only after the owner's approval and his `cargo vet` records; then `tokio` driver (`AsyncSession`, `AsyncRelayQueueTransport`, `StreamProvider`), `transport::tls`, `transport::tor`, the relay's `direct_tls` listener and `spki` command, deny/vet/cooldown/license/NASM gates, mutants/coverage scope (ADR-047 Am. 4). Rows TOR-*, TLS-*, AD-07…AD-12, G-12, P-05, FZ-02, FZ-03, MU-01, COV-01, COV-02, X-01…X-04, X-06, X-10. Handover B→C: green PR run incl. `ct`, `mutants`, `proverif-hx`, `proverif-link`; ⚙ TOR-10/X-10 requested from the owner; report §1 "Phase B closed @ <sha>".
- **C (Sonnet — dictated scenarios; turmoil and the trace are the oracle):** `two-clients` binary, turmoil relay host and `TurmoilProvider`, SIM-*, KS tool and `ks-hour`/`tor-smoke` dispatch jobs, `docs/measurements/M6-traffic.md`, ⚙ coordination. Rows TC-*, SIM-*, AI-07, AI-10, MR-03…MR-07, CT-00, PV-01, X-07, X-08. Closing push = milestone report.

## 6 · Not part of this brief
`secmp-store`, SQLCipher, `Sessions`, `RouteUpdate`, rotation overlap and its re-send rule, `KeyChange`, CLI, the `Api` (M7) · the relay's per-IP / per-circuit HELLO limits, load test, deployment (M10) · any `docs/03` text except the OPEN-M6-07 erratum after owner approval · ADR-018 acceptance (owner, after the report).

## 7 · First step, concrete (Phase A)
`git checkout -b m06-transport 6300b653d0f1f176b7a31470910d5214fa87b9cc`; commit 1 as §3 = `docs(m6): plan, test spec, OPEN-M6, ADR-051 proposed`. Then, in this order: G-04 (allowlist gate, workspace-only), G-01…G-11; `clock` + `TimingRng`; `Session::prepare` (AD-01…AD-06); scheduler core (S-*), back-off (LR-*), outbox (OB-*), pool (QP-*), ControlOps (CO-*); `VirtualDriver`; AI-*, MR-01/MR-02; Kani, proptest, fuzz, X-05, X-09. `cargo xtask ci-fast` after every unit, `ci-full` before the closing return block.

## 8 · Report and evidence
`docs/templates/milestone-report.md` → `docs/reviews/M06-report.md`. With every phase: gate logs under `docs/reviews/M06-evidence/` (Kani incl. the K-02 negative control, fuzz logs with `cov:`/`ft:`/`lim`, mutants verdict per package, coverage per crate, AI-01…AI-06 max |Δt| per mode, MR-01/MR-02 numbers). Closing message per `CLAUDE.md` §7: head SHA, test counts per TEST-SPEC section implemented / passing / extra, one line per F-M6 item, `modell=<id>`, `Modellmix: Opus n · Sonnet n · Haiku n`. No prose repeating this brief, no hypotheses, no recommendations.

## 9 · Return block (end of every phase)
```
PHASE: A|B|C  BRANCH: m06-transport  HEAD: <40-hex sha>  BASE: 6300b653d0f1f176b7a31470910d5214fa87b9cc
ROWS: implemented <n>/<n of phase> · passing <n> · extra <n> (names)   CI-LOCAL: ci-fast <ok|fail> · ci-full <ok|fail>
GATES: kani <n>/<n> · fuzz <n> targets · mutants <pkg: caught/missed/unviable> · coverage <crate: %>
BLOCKED: <row ids + reason | none>   STOP: <none | reason>   modell=<id>
```

## 10 · STOP (CLAUDE.md §6 in full, plus)
A dictated row contradicts the spec; a reading beyond OPEN-M6-01…26 is needed; any third-party crate in Phase A; a [DEP] row before ADR-051 Part 2 is approved; a crate younger than 7 days, an advisory, or a license outside ADR-051; `unsafe` outside `secmp-sys-*`; any frame written at a time that depends on activity (AI-* red) — root cause in code, never a tolerance change; a frozen vector would change; a gate red without a found cause; anything needing an owner decision.

## 11 · Owner prerequisites
(1) ADR-051 Part 2 approval and the owner's `cargo vet` trust records (before Phase B). (2) OPEN-M6-03, -05, -06, -07, -17, -20 (substitutes), -21 (GitHub VM as "real hardware"), -22 decisions or their defaults (+24 h after delivery). (3) ⚙ test relay with C tor and the M6 relay build with `direct_tls`, a second machine, the Windows 11 VM (TOR-10, X-10, TC-07, TC-08, MR-04, MR-05, AI-07 Tor part). (4) After the report: ADR-018 and OQ-4.
