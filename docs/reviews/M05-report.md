# Milestone report — M5 SecMP-LINK + SecMP-Q + relay core + in-process harness

Branch: `m05-link` · Base: `a229dbfc9dfe57dd0957359044389eb3b6654b32` · Author: Claude Code · Date: 2026-10-07
Phase A: `modell=claude-sonnet-5-5`

## 1. Plan (written before implementation, updated during)

Binding inputs: `docs/reviews/M05-planning/` (`BRIEF_M5.md`, `TEST-SPEC-M5.md`, `ADR-048-proposed.md`, `CLAIMS-LINK.md`,
`OPEN-M5-decided.md`). ADR-048 and the owner-class items (o), (p), optional (q) were ratified by default on
2026-10-04 20:45 UTC (brief §11 (1)); the [SQ-n], [O-1], [O-2], [O-6] rows are in scope from the start.

Phases and handover: A (this conversation, Sonnet) → B (Opus) → C (Sonnet). Handover row: "Phase A closed @ `<sha>`".

| Step | Phase | What | TEST-SPEC rows closed | Status |
|---|---|---|---|---|
| 1 | A | Commit 1: planning files, ADR-048, CLAIMS §LINK, reference files, SCHEMA rev-6 delta, this plan, M2 coverage table | — | done (commit 1) |
| 2 | A | `secmp-proto::link`: constants, derived ids (rid/sid/akc), D.6 signing and token helpers | P-05 | open |
| 3 | A | Link handshake, client and relay (sans-IO): HELLO/RELAYINFO/HS1/HS2 | C-01…C-22, RH-01…RH-15, P-01 | open |
| 4 | A | Frame codec `Link::seal/open`, counters, `LINK_MAX_FRAMES`, CONT assembly, request/response framing helpers | F-01…F-10, F-12, P-02…P-04 | open |
| 5 | A | Vector replay of the client/relay handshake groups from `vectors/ref/link.json` (Rust side of the link-A cases 0001–0005, 0052–0059, 0060–0074) and file-shape check | V-01…V-05, V-17…V-19, V-21 | open |
| 6 | A | R-55, R-56 | G-03, P-12 | open |
| 7 | A | Kani harnesses | K-01…K-04 (K-08 per table below) | open |
| 8 | A | Fuzz targets (+ committed seeds) incl. hx mode 3 | FZ-01…FZ-06, FZ-09 | open |
| 9 | A | `cargo xtask ci-fast`, push, PR, `ci-full`-equivalent CI run; handover | — | open |
| B | B | relay crate, link-A vector groups (V-06…V-16, V-20, V-22), Q-*, RL-*, G-01, G-02, ct, K-05…K-07, FZ-07, FZ-08, formal, xtask | see brief §5 | not started |
| C | C | transport, harness, hx re-freeze rows | see brief §5 | not started |

### M2 coverage of D.1 records and D.2 requests/responses (decides K-08 and P-13)

| Item | Existing M2 artefact | Decodes | Covers |
|---|---|---|---|
| property | `crates/secmp-proto/tests/canonical.rs::records` | `Hello`, `RelayInfoV1`, `RelayInfoRecord`, `Hs1`, `Hs2` (D.1) | decode(encode(x)) = x; mutants canonical |
| property | `crates/secmp-proto/tests/canonical.rs::frames` | every `Request` / `Response` (D.2 incl. `CONT`, all `CELLR` contexts) | same, incl. `check_bytes` and `mutants_are_canonical` |
| Kani | `request_queue_new`, `request_skey`, `request_send`, `request_fetch`, `request_queue_del`, `request_link_put`, `request_link_get`, `request_ping`, `request_cont`, `request_fetch_multi` | request decoder, plaintext length 4335/4336/4337 per opcode | total, exact-fit |
| Kani | `response_frame` | response decoder, both `CELLR` contexts, lengths 4335/4336/4337 | total, exact-fit, opcode preserved |
| Kani | — | no harness runs the request and the response decoder in one proof | — |

Decision from the table: **P-13 not dictated** (`canonical.rs::records` and `::frames` cover all four D.1 records and every
D.2 request and response). **K-08**: the condition "no M2 harness runs both decoders" holds literally (the request
harnesses and `response_frame` are separate proofs); K-08 is therefore treated as dictated and is implemented in step 7.

## 2. What was built

Commit 1 (docs/vectors only): planning artefacts, ADR-048 (appended to `docs/08`), `formal/CLAIMS.md` §LINK, `docs/07`
status line, `vectors/ref/link.json` and the reference LINK files, `vectors/SCHEMA.md` rev-6 delta.

## 3. Evidence per acceptance criterion

Reference-file check (commit 1): `shasum -a 256 vectors/ref/link.json` =
`dd77bb7c96d298f9cc188d4eadbd950605ccca2a250169708cdc573a73264c77`, `stat -f %z` = 2 818 910.
`vectors/SCHEMA.md` vs the reference copy (`target/fable/m5/ref/SCHEMA.md`): remaining differences are only the revision-7
header line and the §4.10 pointer (Phase C, hx re-freeze); output in `docs/reviews/M05-evidence/schema-diff.txt`.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci` | pending |

## 5. Deviations from spec / plan

- Reference files copied by the reviewer (WEISUNG M5-1), `<SECMPROREF>` = `target/fable/m5/ref/`.
- `vectors/SCHEMA-4.11-link.md` sits at `vectors/` (as delivered by the reviewer), not under `vectors/ref/`.

## 6. Dependencies added or bumped

None yet.

## 7. Open risks and known limitations

None recorded.

## 8. Blocked / questions for the reviewer or owner

None.

## 9. Checklist before requesting review

Not yet applicable.
