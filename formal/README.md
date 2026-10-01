# formal/ — ProVerif models

Symbolic models of the SecMP/1 message flows (docs/06 §4 "Formal", §5 step 10):

| Model | Milestone | Scope |
|---|---|---|
| `tr.pv` | M3 | SecMP-TR, bounded 3 steps: secrecy, FS, PCS with and without a DH oracle, header confidentiality |
| `hx.pv` | M4 | SecMP-HX: SK secrecy, injective agreement on the transcript, identity confidentiality under `K_id` |
| `link.pv` | M5 | SecMP-LINK |

`CLAIMS.md` lists the queries — including those expected to be false — and is **fixed by the reviewer before
modelling** (ADR-026). A model change requires a spec change reference.

The gate (`cargo xtask step proverif`, part of `ci-full`) requires ProVerif 2.05 (a missing prover fails), runs
a self-test with one query that must be true and one that must be false, and runs exactly the models listed in
`xtask/src/expect.rs` (`PROVERIF_MODELS`). Model files start with `(* SPDX-License-Identifier: AGPL-3.0-or-later *)`.

For each model the gate compares the verdicts of its `RESULT` lines, in order, with `expect::PROVERIF_EXPECTED`
(runs of `CLAIMS.md` IDs with their expected verdict): the number of lines must match, a query expected true must be
proved, a query expected false must be refuted (ProVerif reports an attack), an informative query may give anything;
a unit test checks the table against the "Expected" column of `CLAIMS.md`.

Status: M3 — `tr.pv` (39 `RESULT` lines: T1–T6, T8, T9, T11 true; T7, T10 false; T12 informative, false) is in
`PROVERIF_MODELS` and checked by the gate; `hx.pv` and `link.pv` follow in M4 and M5.
