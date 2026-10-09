# formal/ — ProVerif models

Symbolic models of the SecMP/1 message flows (docs/06 §4 "Formal", §5 step 10):

| Model | Milestone | Scope |
|---|---|---|
| `tr.pv` | M3 (F5, T13: M4; T14: M5) | SecMP-TR, bounded 3 steps: secrecy, FS, PCS with and without a DH oracle, header confidentiality; per-slot in-order/other-first receive branches; replay after a skipped-path acceptance (T14) |
| `hx.pvl` + `hx/<session>.pv` | M4 | SecMP-HX: SK secrecy, injective agreement on the transcript, identity confidentiality under `K_id`; one file per session over the library (CLAIMS O-18, ADR-046), plus `hx/<session>-auth.pv` with the begin-`IStart` declaration for hClean, hKEM, hDH, hKCI, hKCIlt (O-22) |
| `link.pvl` + `link/<session>.pv` | M5 | SecMP-LINK with the SecMP-Q command binding: relay authentication (classical, PQ, both broken, `relay_sig` revealed), frame confidentiality, integrity/order/replay, forward secrecy, `sess_id` binding of command signatures, `akc` pinning; one file per session over the library (CLAIMS §LINK LO-1, OPEN-M5-16 A): lClean, lDH, lKEM, lBoth, lSig, lFS, lFSDH, lFSEph, lQKey |

`CLAIMS.md` lists the queries — including those expected to be false — and is **fixed by the reviewer before
modelling** (ADR-026). A model change requires a spec change reference.

The gate (`cargo xtask step proverif [--models tr|hx|link|all] [--jobs N]`, part of `ci-full`) requires ProVerif 2.05
(a missing prover fails) and runs a self-test with one query that must be true and one that must be false. `tr` runs
`proverif formal/tr.pv`; `hx` runs `proverif -lib formal/hx.pvl formal/hx/<file>.pv` for every file of
`formal/hx/` (19: 14 session files, 5 `-auth` files); `link` runs `proverif -lib formal/link.pvl
formal/link/<file>.pv` for every file of `formal/link/` (9 session files); `all` is all three. The files run in
parallel (at most 4 processes), each capped at 30 minutes — a timeout fails, naming the file and its last progress
line. Model files start with `(* SPDX-License-Identifier: AGPL-3.0-or-later *)`.

`tr.pv`'s verdicts are compared, in order, with `expect::PROVERIF_EXPECTED` (runs of `CLAIMS.md` IDs with their
expected verdict). Each `hx/<file>.pv` is compared with its entries in `expect::PROVERIF_EXPECTED_HX`, each
`link/<file>.pv` with its entries in `expect::PROVERIF_EXPECTED_LINK` (file, `CLAIMS.md` ID, query text, verdict),
matched by query text and order: a missing, extra or re-ordered `RESULT` line fails. A query expected true must be
proved, a query expected false must be refuted (ProVerif reports an attack or reachability), an informative query may
give anything. Every model file's SHA-256 is pinned in `expect::PROVERIF_MODEL_SHA256` (ADR-046 Amendment 1). CI:
`linux-full` runs `--models tr` and delegates its step `proverif-link` (`--delegated proverif-link`), the job
`proverif-hx` runs `--models hx --jobs 4` (ADR-046), the job `proverif-link` runs `--models link --jobs 4` (M5).
