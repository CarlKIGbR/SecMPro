# M06 review — acceptance record

Reviewer: Fable (reviewer, planner session) · Date: 2026-10-27 · Branch `m06-transport` → `main`, PR #9 (merged) · Report: `docs/reviews/M06-report.md`
Pin: `main` = `bf550999fb2c7771153863f1da2f19adb5a677b5` (squash of PR #9, "M06 transport (#9)", merged 2026-10-27 18:01:49 UTC; GO by the reviewer under the owner delegation of 2026-09-29; gate `MERGE 9 86de568b…` 18:01:37 → MERGED 18:01:44). Last PR head before the squash: `86de568b9c47602b1de8bb8f2fb422517cf1442c`.
Verdict: **ACCEPTED BY PHASE ACCEPTANCE AND EXTERNAL ADJUDICATION**

No directorate review (planning cells, lenses, verifiers, red team) was run for M6. Reasons: owner delegation; every phase was accepted on a fully green PR run; three external rounds (Astra FINAL4, FINAL5, FINAL5b) were adjudicated and their findings closed. A later directorate review of `main` remains possible.

## Phase acceptances

| Phase | Acceptance SHA | PR run |
|---|---|---|
| A | `8a31d4f` | 38657149405 |
| B | `6f6c7a8` | 39080358115 (#160) |
| C1 | `25625bc` | 39660191651 (#165) |
| C2 | closed @ `cbf0284` / `7c924bc`; final head `86de568` | 40519100622 (#194), 23/23 jobs green incl. `ci-verdict` |

## External rounds

| Round | Pin | Findings | Closure |
|---|---|---|---|
| Astra FINAL4 | `007e5b2` | 2 blockers + 5 low | fixed in C-6 |
| Astra FINAL5 | `25625bc` | 1 environment blocker + 2 low | closed (FIN5-1/2/3) |
| Astra FINAL5b | `e751a3c` | 3 medium + 3 low (all confirmed by the Opus verifier; no product code) | fixed in C2-18 / 18b / 18c (head `f71281b`) |
| GLM EXT7 | — | no report | — |

Adjudications (project knowledge): `claude/EXT-M6A…` (A rounds), `claude/EXT-M6B…` (B rounds), `claude/EXT-M6C1-adjudication-2026-10-21.md`, `claude/EXT-M6C2-FINAL5b-adjudication-2026-10-26.md`.

## Deferred list

`docs/reviews/M07-planning/OPEN-M7.md` (arrives with M7 commit 1) and `docs/reviews/M06-report.md` §7 (open risks and known limitations).

## Open owner-operated rows

TC-07, TC-08, AI-07 Tor part, MR-04, MR-05 VM part, TOR-10, X-10 (invocations: `M06-report.md` §6). Also open after the merge: removal of the Azure federated credential for `refs/heads/m06-transport`; smoke `hello` (`gh workflow run win-ondemand.yml --ref main -f suite=hello`), dispatched 2026-10-27.

Signed: Fable (reviewer), 2026-10-27
