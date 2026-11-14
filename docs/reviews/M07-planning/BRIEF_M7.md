# BRIEF M7 — client core: identity, contacts, store, invitations, sessions, CLI (final, Phase A; decisions of 2026-10-27 19:30 UTC applied)

Date: 2026-10-27 · Reviewer: Fable · Executor: container `secmp-main` · Base: `main` =
`bf550999fb2c7771153863f1da2f19adb5a677b5` (M6 squash) · Branch: `m07-client-core` · Phases and models (full ids,
`.fortsetzung` always before `.modell-`): **A** `BRIEF_M7.modell-claude-opus-5-5.md` · **B**
`BRIEF_M7-B.modell-claude-sonnet-5-5.md` (+ one Opus weisung for the scheduler-core rows SC-*) · **C**
`BRIEF_M7-C.modell-claude-sonnet-5-5.md`; instructions `WEISUNG_M7-k.fortsetzung.modell-<id>.md`; every report
carries `modell=<id>`.

Pin line (first command): `git fetch origin && git checkout -b m07-client-core bf550999fb2c7771153863f1da2f19adb5a677b5`

## 0 · How this milestone is run
You implement; the reviewer plans, judges and reviews. The tests are **dictated** in
`docs/reviews/M07-planning/TEST-SPEC-M7.md` (174 rows: A 63, B 71, C 40; 2 "(cond, not built)", 3 waiting for an owner action): every row of your phase under its exact name;
helpers allowed; every extra test named in the report; no row dropped, no expectation changed — a row that contradicts
the spec is a STOP with the row id and the spec line. [O-n] rows follow `OPEN-M7-decided.md` (owner items: built as the default until the owner rules); **[O-01] rows are built only after the owner has written "ADR-053 accepted" — there is no silent default**; [DEP] rows wait for the
ratified dependency set (OPEN-M7-03); [REF] rows wait for `vectors/store.json` from `ref/` (OPEN-M7-38); "(cond, not built)" rows
are dictated but not built unless the decision flips. Reports carry numbers, run IDs, SHAs and verdict lines — never an
assessment of your own work, never a proposal. No agent worktrees. **No push by the executor: end each phase with the
return block; the reviewer pushes via the gate (`sp.sh push`).**

## 1 · Order = reference
`docs/07-milestones.md` §M7 (`docs/07:137-150`: deliverables `:140-143`, acceptance `:145`, review focus `:147`,
obligation `:149`), `CLAUDE.md`, DoD `docs/06` §8, guard rails `docs/06` §9; `docs/02` §4.2 (`:86-104`), §4.3
(`:106-119`); `docs/04` CS-2.2 (`:44-45`), CS-3.1…CS-3.7 (`:52-58`), matrix `:89`; spec `docs/03` §5 (`:186-261`), §6.5–§6.7
(`:327-370`), §7.5–§7.8 (`:479-519`), §9.1 (`:580-593`), §9.8 (`:639-650`), §10.4–§10.6 (`:680-699`), §11.3 (`:717-725`),
§12.2 (`:746-748`), App. A (`:756-774`). ADR-020, ADR-027 (M0 outcome), ADR-042, ADR-044 (d)/(f), ADR-048 (m), ADR-051.
The spec is not repeated here. Nothing in this brief decides an owner question (OPEN-M7 class "owner").

## 2 · Container rules
Commit on `m07-client-core` only. Allowed: `sleep`, `timeout`, `tee`; long gates in the foreground. Not allowed:
`taskset`, reading `/proc`, `cp -r`, `docker`, `ssh`, `rsync`; `gh` read-only. No network in any test except the
loopback E2E rows named in TEST-SPEC (`docs/06:114`); E2-07 (Tor) is a dispatch job, never a required one.

## 3 · Binding artefacts (commit 0 and commit 1)
Material: `target/fable/material/M7/` (inside the repo, gitignored); missing → STOP with `ls target/fable`, search nowhere else.
**Commit 0** = `docs(m6): review record and status` (decision 06 / Q85): copy `docs/reviews/M06-review.md` unchanged
from the material dir and apply the `docs/07:133` status line from the material dir ("merged 2026-10-27 (#9, `bf55099`)").
**Commit 1** = `docs(m7): plan, test spec, OPEN-M7, proposed ADRs`: copy unchanged into `docs/reviews/M07-planning/`:
`TEST-SPEC-M7.md`, `OPEN-M7.md`, `OPEN-M7-decided.md`, `BRIEF_M7.md`, `ADR-053-proposed.md`, `ADR-054-proposed.md`,
`ADR-055-proposed.md`; append the three ADRs to `docs/08` as **Proposed** (next free number after ADR-052, `docs/08:865`);
write `docs/reviews/M07-report.md` §1 (plan: phases A–C, A-1…A-4, which rows each step closes) and the `docs/07` §M7
status line. Code only after commit 1.

## 4 · Obligations carried into M7 — each is a deliverable (row ids in TEST-SPEC (m))
M4 review: F-M7/C-12/R-26 (transactional accept, `docs/07:149`), RT-1 (24 cells, group spent), R-69, RT-2 (no `kat`
in release), RT-3 (code; the `docs/01` sentence is the owner's, OPEN-M7-30). M3 review: F27, F29, F30, F31 (F28 = owner,
OPEN-M7-33). M5 review: F-13, F-14, R-146 (OPEN-M7-32). M6 (`M06-report.md` §5, §7, §8): D-C2-1, OQ-19 (owner, OPEN-M7-07: M7 builds B — no time-based re-send, `NotConfirmed` event, row SE-13b; the reviewer's
recommendation A to the owner is carried as ADR text in the memo, row SE-13a dictated, not built), OQ-20 (OPEN-M7-08), FIN5b-1, frame id, Kani rest, OPEN-M6-C1-1, OPEN-M6-C1-2, OPEN-M6-C1-3 (sbom),
OPEN-M6-B-3, OPEN-M6-B-5 (owner, default "not M7"), ADR-045 Am. 10 M7 note (harness job), budgets pin, mutants suite,
`m0_early` ordering. Not M7 (reason): ADR-018/OQ-4 (owner decision after `docs/measurements/M6-traffic.md:102`); OS
keystore wrap CS-3.2 (b) (OPEN-M7-31, M9); skipped-key age bound F28 (spec change, owner); fast-forward budget code F25
(measured only, OPEN-M7-34); `crypto-bigint` `--ignore` stays until Arti moves (ADR-051 Am. 6, `docs/08:861`).

## 5 · Phase split and handover
- **A (Opus — no oracle for the dependency unification, the C builds on three targets, the store's transaction design
  and the new ct target; the spec and CS-3 are the oracle for the rest).** Order = TEST-SPEC "Phase A order"; every
  non-[O-01] row first; no commit may leave `ci-fast` red. **A-1** (no dependency change, no store code): G7-00 only in
  the first commit after **2026-10-30 02:00 UTC** (remove `ctutils` from `COOLDOWN_EXCEPTIONS`, `expect.rs:148-153`, and
  re-dictate `cooldown_covers_m6_lock`, `cooldown.rs:562-564`; ADR-015 list (3) "expired, entry removed"; the gate is red
  from **2026-10-31 00:00 UTC** until it lands); G7-05, G7-07…G7-10, G7-12, G7-16, CT-04; step **A0** = the ADR-055 probe
  (report only, incl. `fuzz/Cargo.lock` and a cargo-fuzz sanitizer build of the OpenSSL/SQLCipher C code; no
  `Cargo.toml` change). **A-2** (after the A0 report, "ADR-055 accepted" and the owner's vet records): G7-01…G7-04,
  ST-08. **A-3** (store code with the `kat`-only test key, no ADR-053 construction): G7-06 first (client-core and testkit → store edges),
  then ST-01…ST-04, ST-09, ST-13…ST-18, PC-* (PC-07 introduces `to_parts`/`from_parts`), G7-18, G7-13, G7-14. **A-4** (only after "ADR-053 accepted"): ST-05…ST-07, ST-10…ST-12, ST-19,
  CT-01 with CT-05, CT-02, BK-*, FO-03, FZ-01/FZ-02 with G7-15a; ST-10, BK-04 stay [REF]-open. Not accepted when A-3 is
  green: return block "A-4 waiting"; Phase B may start on the A-3 head (PR-03, IN-03 wait); A-4 lands before C closes.
  Handover A→B: green PR run on every required and pinned job; report §1 "Phase A closed @ <sha>" (or "A-3 closed").
- **B (Sonnet for dictated rows; Opus weisung for SC-01…SC-10 — the scheduler core and its Kani proofs have no oracle
  beyond the AI/Kani rows, as M6 showed):** `secmp-client-core` `Profile`, `Contacts`, `Invitations`, `Sessions`
  (actor, RouteUpdate, rotation with overlap, KeyChange, reset, receipts), `Api`, settings, relay-view model, transport
  boundary; the transactional accept; the handshake as scheduled ops (D-C2-1). Rows PR-*, IN-*, SE-*, AP-*, SC-*, G7-15b,
  FZ-04, K7-01. Handover B→C: green PR run; report §1 "Phase B closed @ <sha>".
- **C (Sonnet — dictated scenarios; relay, harness and the store are the oracle):** `secmp-cli` (OPEN-M7-12/13), E2E
  rows, FO-01, FO-01a, FO-02, CT-03, FZ-03 with G7-15c, CL-*, G7-21 (`secmp-cli` allowlist row), C-T1, C-T3, G7-17 ⚙; owner-action rows G7-11
  (`miniz_oxide` vet record), G7-19 (ADR-018 accepted), G7-20 (`harness` in the ruleset); not built: C-T2, SE-13a; nightly dispatch `e2e-tor` ⚙ (E2-07), `two-clients`
  moved onto the M7 path. Closing push = milestone report.

## 6 · STOP (CLAUDE.md §6 in full, plus)
A row contradicts the spec; a reading beyond OPEN-M7-01…41 is needed; **any [O-01] row before the owner's "ADR-053
accepted"** (CLAUDE.md §5: never invent a construction); any `Cargo.toml` dependency change before ADR-055 and the owner's vet
records; A0 shows that `rusqlite`/`libsqlite3-sys` cannot be shared with Arti, or a crate < 7 days, an advisory, or a
license outside the allowlist; `unsafe` outside `secmp-sys-*`; any frame whose time depends on activity or store
latency (SE-19, AI-* red) — root cause in code, never a tolerance change; a frozen vector would change (the
`RatchetStateV1` layout included); a Kani bound would have to be lowered; a gate red without a found cause; anything
needing an owner decision (OQ-19, OQ-10, OQ-11, view-once receiver side, duplicate IKS policy).

## 7 · Evidence rules
`cargo xtask ci-fast` after every row group (one section letter of TEST-SPEC), `cargo xtask ci-full` before each
phase's return block. **Registration rule (Q121):** every gate registration (`CT_TARGETS`, `CT_INFORMATIVE_TARGETS`,
`CT_TARGET_SITES`, `KNOWN_SITES`, `FUZZ_TARGETS` + corpus, `KANI_HARNESSES`, a `NORMAL_DEPENDENCY_ALLOW` edge) lands in
the same commit as the target, harness or dependency it registers — never earlier, never later. Gate logs under `docs/reviews/M07-evidence/`: A0 probe, vet/deny/cooldown outputs, ct report
with `store_unlock_reject` and the informative targets, mutants verdict per package (`secmp-store` new), coverage per
crate, Kani incl. SC-06…SC-09 with `VERIFICATION` lines and peak RSS, fuzz logs with `cov:`/`ft:`, PC-05 key-digest
summary, PC-13 bytes/day, CT-03 medians, FO-01 scan summary (files, bytes scanned, canary hits = 0), E2-* run times.
Report sections (`docs/templates/milestone-report.md`): §1 plan, §2 built, §3 evidence per acceptance item and per row,
§4 gates, §5 deviations (must be empty or ADR'd), §6 dependencies (ADR-055 as landed), §7 risks, §8 blocked/questions.
Closing message per CLAUDE.md §7: head SHA, rows implemented/passing/extra per section, one line per obligation of §4,
`modell=<id>`, `Modellmix: Opus n · Sonnet n · Haiku n`. No prose repeating this brief, no hypotheses, no
recommendations.

## 8 · Return block (end of every phase)
```
PHASE: A|B|C  BRANCH: m07-client-core  HEAD: <40-hex sha>  BASE: bf550999fb2c7771153863f1da2f19adb5a677b5
ROWS: implemented <n>/<n of phase> · passing <n> · extra <n> (names) · open [DEP]/[REF]/⚙ <ids>
CI-LOCAL: ci-fast <ok|fail> · ci-full <ok|fail>   GATES: kani <n>/<n> · fuzz <n> targets · ct <verdict>
          mutants <pkg: caught/missed/unviable> · coverage <crate: %>
BLOCKED: <row ids + reason | none>   STOP: <none | reason>   modell=<id>
```

## 9 · Owner prerequisites (memo with +24 h defaults where the class allows)
(1) ADR-053 store key hierarchy and the new labels (spec rev 2.7) — explicit "ADR-053 accepted", no default; gates A-4. (2) ADR-054 application
payloads (`docs/03:509` "before M7"). (3) ADR-055 dependency set and the vet records (named human: `rusqlite`, `argon2` + crypto-closure deps; `miniz_oxide`
for G7-11) — after the A0 report; gates A-2; SQLCipher pin 4.10.0 instead of CS-3.1's "4.17.0" (Q119).
(4) OQ-19 (reviewer recommendation A; M7 builds B until decided), OQ-10, OQ-11, OPEN-M7-21, -23, -25, -27, -28,
-29, -30, -31, -33, -34.
(5) `ref/` session for `vectors/store.json` (OPEN-M7-38). (6) Ruleset: add `harness` (and `fuzz`, if missing) → G7-20; an ADR-018 acceptance → G7-19.
(7) ⚙ test relay with C tor for E2-07; Windows VM for G7-17.
