# PRUEF-M5 — adversarial check of the M5 planning artefacts (2026-10-03)

Checked: `TEST-SPEC-M5.md` (224 rows), `ADR-048-draft.md`, `CLAIMS-LINK-draft.md`, `OPEN-M5.md`, `BRIEF_M5-draft.md`.
Against: `03-protocol-spec.md` rev 2.5 (line numbers of that file), `07-milestones.md` §M5 (:101–113), `06-engineering-standards.md`,
`02-architecture.md`, `BRIEF_REF_M5.md`, `ref-SPEC-QUESTIONS-M5-part.md`, `ref-SCHEMA-4.11-link.md`, `ref-link-cases-index.txt`,
`ref-SCHEMA.md`, `M04-review.md`, `CLAIMS.md`, `TEST-SPEC-M4.md`, `BRIEF_M4.md`.

Method. All 224 rows read. Every docs/03 anchor of TEST-SPEC (113 distinct lines) resolved mechanically against rev 2.5 and read.
Expectation content checked row by row for V, C, RH, F, Q, RL, G, CT, K, FZ, PV (195 rows); T, H, P, X read in full and checked
against §12.1, docs/07:109, docs/06 §4 and M04-review. All sizes/counts recomputed from D.1/D.2/D.6/§4.2. Case coverage, ids,
names and counts checked by script.

## Verdicts

| Check | Verdict | One line |
|---|---|---|
| P1 Spec anchoring | findings 6 | Anchors are right except `:829` (fence; echo is `:827`); unsupported expectations: Q-55 (contradicts O-4 order), RL-18 (stricter than docs/06 :40), T-10 (network in a unit test, docs/06 :93), H-07 (outbox semantics outside M5), X-07 (planner-chosen classes). |
| P2 Frozen vectors | findings 1 | 86/86 ids covered exactly once; groups 27/23/1/8/11/4/12, op/party counts (R 23, C 17, CR 46), outputs, sizes, `link_post`, `resp_counts`, S10 `sess_id 009c442d…` all match SCHEMA-4.11; only V-22's comparison contradicts BRIEF §2/V-25. |
| P3 Frame counts and sizes | ok | Every stated size/count recomputed and correct (shape table 165/37/6/5/22/4181/93/4126/6+88n/85/4314+4106+4106/86/4167+4106+4106/5; 1677, 180, 128, 35, D.6 135/4146/59/60/55/155/55, HS offsets, 8260/12360, 168/720). Shape *exceptions* (ERR 6 stale, ERR 7) are judged under P4/P6. |
| P4 Contradictions | findings 6 | Q-55 vs O-4; RL-07/RL-13 vs ADR-048 (h)/D.2 exception; Q-57 vs SQ-26 and unmarked SQ dependencies; missing [O-7]; missing [HX-RF] on H-02/G-06; H-07 vs M5 scope. |
| P5 Names / markers / counts | findings 3 | 224 rows, ids contiguous, no duplicate, all names snake_case; header counts exact (25/144/10/12/7/9/6/3/8; A 74, B 123, C 27); but PV-01…03 have no name, 2 M4 names reused, marker legend gaps. |
| P6 ADR-048 | findings 5 | (i) all OPEN-1…13, (a)–(g), SQ-26…28 transcribed with correct numbers; (ii) E-1…E-7 match R-60…R-65/D-04/05/07/08/11/27/28 and docs/02:111 holds "HandshakeInit"; (iii) formula = §9.1 :582 + App. A :761, 16 B, but anchor `:203` wrong and case ids not named; (iv) RT-3 matches; (v) status line present; (vi) owner-class OPEN-M5 items missing, implicit REF-M5 r.6, wrong veto consequence. |
| P7 CLAIMS §LINK | findings 1 | L1–L9 map onto §11.1 LINK/Q; expected-false lines present (§11.2); M11 split justified (CLAIMS O-8 precedent; docs/07:109 asks only a byte-level test); Q "unlinkability of rid/sid" and operator-side `akc` detectability unaccounted. |
| P8 Brief | findings 3 | 47 lines; F-M5 mapping complete (M04 :164 all 14 items + docs/07:113 + ADR-048 list); phase split = TEST-SPEC (every row once); STOP present; no spec text; SCHEMA copy instruction self-contradictory; A→B handover omits the gate that judges A's Kani/fuzz rows. |
| P9 Gaps | 8 gaps | No docs/07 §M5 acceptance criterion lacks a row; 8 spec/standard obligations lack one (list below). |

## Findings

| PR | Sev | Where | Finding | Smallest correction |
|---|---|---|---|---|
| PR-1 | must-fix | TEST-SPEC Q-55 | A byte-identical replay of QUEUE_NEW or LINK_PUT on a second link fails the `sess_id`-bound token before the signature (order token → signature: REF-M5 reading 1, OPEN-M5-04 A, reading (b)), so the answer is ERR 1, not one of "ERR 4 / present 3 / LINKR {0,0}". | Expected: "ERR 1 (QUEUE_NEW; LINK_PUT after frame 3) · ERR 4 (SEND, QUEUE_DEL) · present 3 (FETCH, FETCH_MULTI entry) · LINKR {0,0} (owner status); link 2 fresh (`last` < cmd_seq)"; add [O-4]. |
| PR-2 | must-fix | ADR-048 (h), (f)/D.2 `:839`; TEST-SPEC RL-07, RL-13, Conventions "Exceptions"; OPEN-M5-01/-02/-06 | The owner-class defaults are wire-visible docs/03 changes (docs/03:3) but have no ADR item: RL-07 expects LINK_PUT ERR 6 although (h) lists LINK_PUT answers without ERR_MALFORMED, and RL-13/Conventions expect one ERR 7 frame for every command although the D.2 exception added by (f) names only the stale `cmd_seq`; OPEN-M5-01 promises an optional ADR item for B that does not exist. After ratification the rows contradict rev 2.6 (STOP). | Add ADR-048 items (o) LINK_PUT `expires_bucket` ∉ [now_bucket, now_bucket + 720] ⇒ ERR_MALFORMED after the third frame (OPEN-M5-06); (p) over-rate request not executed, one ERR 7 frame, `cmd_seq` recorded, as a second D.2 `:839` exception (OPEN-M5-02); (q, optional) OPEN-M5-01 B — each "owner decides, default = OPEN-M5 default". |
| PR-3 | must-fix | BRIEF §2 bullet "Reference files … copied with cp, never edited" | `vectors/SCHEMA.md rev 6` sits in the cp list, but the repo copy carries the reviewer-corrected §4.10 pointer (BRIEF_M4:16 "pointer V1–V9/R1–R13 corrected") while ref rev 6 still says "V1–V8 … R1–R12" (ref-SCHEMA.md:220): cp silently regresses it; the merge list also omits the revision-6 header line and §5. | Move SCHEMA.md out of the cp list: "edit the repo copy: keep §4.10; add exactly the rev-6 delta (revision-6 line, §1 `"schema": 6` bullet, §3 tag `link`, §4.11 pointer, §5 'None …'); `diff` against the ref file shows only §4.10". |
| PR-4 | should-fix | TEST-SPEC Q-57, P-06, K-07, FZ-07, FZ-08, K-04 | Rows exercise SQ-26/SQ-27 behaviour without a marker, so they would build unratified behaviour before the [SQ-n] rows may land; Q-57 "every reachable outcome (… ERR 1–6 …) ⇒ equal count per command" contradicts SQ-26 (stale FETCH/FETCH_MULTI/LINK_GET = 1 frame). | Add [SQ-26] to Q-57, P-06, K-07, FZ-07; [SQ-27] to FZ-08 and K-04's name cell; Q-57: "D.2 count per command, stale `cmd_seq` and ERR 7 excepted (Conventions)". |
| PR-5 | should-fix | TEST-SPEC Q-06, Q-12, Q-33; OPEN-M5-07 Blocks | OPEN-M5-07 lists Q-06 and Q-12 as blocked but neither carries [O-7]; Q-33 "budget full ⇒ ERR 2" is unreachable with the vector budget (OPEN-12: link data does not count) and depends on O-7's link-data pool, unmarked and unlisted. | [O-7] on Q-12 and Q-33 (Q-06 too if it uses the real budget, else drop it from Blocks); add Q-33 to OPEN-M5-07 Blocks. |
| PR-6 | should-fix | TEST-SPEC H-02 (and H-03, H-07…H-10 built on its sessions), G-06; ADR-048 Part 3 | H-02 SENDs to `inv_sid`, which a §9.1 relay knows only when derived (G-05, [HX-RF]), but H-02 is not [HX-RF]; G-06 derives route `sid`s, which may move the Handshake-route bytes of the frozen hx cases, yet is neither [HX-RF] nor in ADR-048's list of changed cases. | Mark H-02 [HX-RF] (dependants inherit); state for G-06 whether hx route `sid`s change — if yes mark [HX-RF] and name the initiate/respond cases in ADR-048 Part 3. |
| PR-7 | should-fix | ADR-048 Part 3 "Consequence"; OPEN-M5-14 B | The changed hx cases are named by class only ("the invite case and every invitee case …"), not by id; and B's "earlier values keep their bytes" holds only if the former 16-B `inv_sid` draw is still drawn and discarded — with "never drawn" (m)/G-05 every later draw of the invite case shifts. | Name the ids (hx-0003 `invite`, per M04 R-60, and the invitee/reject cases that decode its URI, from SCHEMA-4.10-hx.md); OPEN-M5-14 B: "the 16 B formerly drawn for `inv_sid` are drawn and discarded; `invq_recv_seed`, `owner_seed` are appended". |
| PR-8 | should-fix | ADR-048 "Consequences" bullet 1; BRIEF §2 "Items (a)–(l) are binding readings now (the frozen vectors pin them)" | "A veto of (f), (i) or (j) changes those rows only" is wrong: (i) is OPEN-7, pinned by P12–P14, P21, E11–E14; (f)/(j) contain OPEN-5/OPEN-8, pinned by E23, `link_post`, P18, E15; only the SQ parts are unpinned. | "A veto of the SQ-26/SQ-27 part of (f) or the SQ-28 part of (j) changes only the [SQ-n] rows; a veto of anything else in (a)–(l) is a STOP"; BRIEF §2 "… except the SQ-26/27/28 parts of (f) and (j)". |
| PR-9 | should-fix | ADR-048 (h), (k); OPEN-M5-13 | (h) silently encodes REF-M5 reading 6 ("a one-time blob is then deleted" ⇒ `one_time` 0 kept) while reading 5 (LINK_PUT on a consumption marker ⇒ ERR 5, dictated by Q-36), equally wire-visible, is absent; both are still pending OPEN-M5-13. | Append to (k): "A LINK_PUT whose `ld_id` names a consumption marker is ERR_EXISTS until the marker expires; a blob with `one_time` = 0 is returned and kept (REF-M5 readings 5, 6; OPEN-M5-13)". |
| PR-10 | should-fix | TEST-SPEC T-10 | "H-03 … over loopback TCP" in a unit row contradicts docs/06 §4 (`:93` "Nothing that touches the network or wall clock in unit tests"). | Re-file T-10 under (c) as H-11 (unit 143, integration 11) or keep only `tokio::io::duplex`. |
| PR-11 | should-fix | TEST-SPEC RL-18 | "`cargo tree -p secmp-relay`: no ahash/foldhash" is stricter than docs/06 :40 (permitted for maps keyed by relay-generated ids) and can fail on a transitive default hasher. | Keep the type-level assertion (maps keyed by rid/sid/ld_id use `RandomState`); drop the cargo-tree ban. |
| PR-12 | should-fix | TEST-SPEC V-22 vs BRIEF §2, V-25, X-01 | V-22 compares `vectors/rust/link.json` "structurally (generator removed)"; BRIEF §2 says the Rust generator writes `vectors/link.json` byte-identical to `vectors/ref/link.json` (step 12a); V-25 says "= re-frozen ref/hx.json". | One wording for V-22 and V-25: "the Rust generator's `vectors/link.json` equals `vectors/ref/link.json` as step 12a compares it". |
| PR-13 | should-fix | TEST-SPEC H-07; BRIEF §6 | "lost cells re-encrypted and re-sent; every message arrives once" needs outbox semantics, an M6 deliverable (docs/07 §M6 `outbox`); BRIEF §6 says "outbox/receipts (M7)". | H-07: "the scenario driver re-sends the cells it recorded as unacknowledged; every message arrives once; no mk reused"; BRIEF §6: "outbox (M6), receipts (M7)". |
| PR-14 | should-fix | BRIEF §5 Handover A→B | The handover requires only `linux-fast`, `windows-native`, `xwin-cross`, but Phase A's K-01…K-04, FZ-01…FZ-06, FZ-09 are judged in `linux-full` (Kani, fuzz steps): A can close with them unproven. | Add "`linux-full` (or the kani and fuzz step logs of that push)" to the A→B handover. |
| PR-15 | should-fix | CLAIMS-LINK "Paths the model covers / excludes"; L7, L11 | §11.1 Q "unlinkability of rid/sid" is neither claimed nor excluded; L7 proves only that the client's check runs (R honest), not the §11.1 Q property "detectability of per-user access keys" against the operator; L11 has no §11.1 anchor. | Excluded list: "unlinkability of rid/sid and per-user-key detectability against the operator (§11.1 Q): R is honest here — tests Q-01, P-05, C-11, RL-19"; L11: anchor or "beyond §11.1, M11". |
| PR-16 | nit | TEST-SPEC PV-01…PV-03; V-23, FZ-09 | PV rows carry no test name although BRIEF §0 says "implement every row under its exact name"; V-23 `hx_vectors` and FZ-09 `hx_accept_structured` reuse M4 names (deliberate, declared only for V-23). | Name PV-01/02 (e.g. `proverif_link_matches_claims`, `proverif_tr_t14_second_receive`), mark PV-03 "docs, no test"; add "(existing target)" to FZ-09. |
| PR-17 | nit | TEST-SPEC marker legend; Q-07; V-23…V-25, G-04/05, PV-01, X-04/05 | [R5-1] on Q-07 points to reading 1, which OPEN-M5-13 (readings 2–10) does not cover (reading 1 = OPEN-M5-04); rows blocked by OPEN-M5-14/15/16 carry no [O-n]; SCHEMA labels P6, E3, F1, T1, H1 collide with row ids P-06, F-01, T-01, H-01 without a legend line. | Drop [R5-1]; add [O-14]/[O-15]/[O-16]; legend: "P1–P27, E1–E23, I1–I8, H1, S1–S10, T1–T4, F1–F12 = SCHEMA-4.11 case labels". |
| PR-18 | nit | TEST-SPEC Conventions (D.2 shape), Q-52 | `docs/03:829` is the code fence; "`cmd_seq` echoes the request" is `:827`. | `:829` → `:827`. |
| PR-19 | nit | ADR-048 (m) | The field comment of `inv_sid` is `docs/03:202` (`:203` is `inv_send_seed`); the added "pooled recv-queue" sentence goes beyond R-90 (consistent with §10.6 rule 3). | `:203` → `:202`; keep or drop the pooled-queue sentence explicitly. |
| PR-20 | nit | ADR-048 E-4, E-6, E-8 | E-4 "handshake cells" vs D-04 "handshake cell"; E-6 re-anchors to rev 2.6 where D-27 says rev 2.5; E-8 lists "(a)–(n)" though (e) adds no docs/03 text. | State the deviation from D-04/D-27 in one clause; E-8 "(a)–(d), (f)–(n)". |
| PR-21 | nit | TEST-SPEC X-07 | The two unpad classes are "planner's choice"; R-93 names none — not backed by a source. | Mark [O-n] (reviewer decides) or take the classes from the M4 register row R-93. |
| PR-22 | nit | TEST-SPEC G-01 | "attempts = \|distinct skipped hks\| + 2 in every case" is undefined when `hk_r`/`nhk_r` is None (§7.4 :440 "Open() with an absent key fails"). | Add "(states with `hk_r`, `nhk_r` set; an absent key costs one dummy open)". |

## Gaps (no row)

1. D.2 response value rules at the client decoder — `:832` `evicted_id` ≠ 0 with `evicted_present` 0; `:833` CELLR `present` ∉ 0..4, `present` 0 with non-zero `rid`/`cell_id`, FETCH `present` 1 with `rid` ≠ 0, `present` 2–4 with `cell_id` ≠ 0; `:834` LINKR flags ∉ {0, 1}; response CONT `idx` ∉ {1, 2}. F-10 covers op/padding only, Q-59 only the relay's own output.
2. Relay request decoder negatives beyond `mode`/`count`/CONT: LINK_PUT `one_time` ∉ {0, 1} (REF-M2 r.5) and non-zero trailing bytes after the last field of a non-SKEY request (`:149` consistency rule, §9.7 (7) `:632`) ⇒ teardown.
3. §9.7 (1) `:626`: the inviter re-issues the identical LINK_PUT when owner status reads {0, 0} before `expires` — RL-01 checks only the {0, 0}; H-07 covers queues only.
4. §9.3 `:608`: "every delivered cell is acknowledged, whether or not it decrypted" — no harness row with an undecryptable delivered cell.
5. OPEN-M5-02 default "HELLO→HS1 timeout 30 s" has no row; the ERR 7 timing of a rate-limited LINK_PUT (frame 1 or after frame 3) is undefined.
6. docs/07:105 deliverable "config" — no row (missing/invalid config refuses start; budget and rate values taken from config).
7. §4.1 `:154` + docs/06 §4 "proptest for encodings (canonical)" for D.1 records and D.2 payloads — only fuzz (FZ-01, FZ-05); cite the M2 wire property if it exists, else add one P row.
8. docs/06 §4 Kani "frame parsers (no panics, exact-fit)" for the D.2 request/response decoder — K-01 covers pad/unpad only; cite M2's harness or add one.

docs/07 §M5 acceptance (`:109`) and review focus (`:111`): every item has at least one row (TEST-SPEC (j) maps verified).

fit for delivery after must-fixes: yes

## Applied (planner, 2026-10-03, with the reviewer's OPEN-M5 decisions)

| Item | Change |
|---|---|
| PR-1 | Q-55 expected per command: ERR 1 (QUEUE_NEW; LINK_PUT after frame 3), ERR 4 (SEND, QUEUE_DEL), `present` 3 (FETCH, entries), LINKR {0,0}; second link with `last` below the replayed `cmd_seq`; [O-4]. |
| PR-2 | ADR-048 Part 4b: (o) `expires_bucket` range ⇒ ERR_MALFORMED after frame 3; (p) ERR 7, not executed, `cmd_seq` recorded, LINK_PUT after frame 3, HELLO over limit closed, as the second D.2 `:839` exception; (q) optional OPEN-M5-01 B (default not adopted). RL-07 cites (o), RL-13 cites (p) incl. LINK_PUT timing; Conventions "Exceptions" cite (f), (p); C-12 cites (q). |
| PR-3 | BRIEF §2: `vectors/SCHEMA.md` removed from the cp list; edit the repo copy with exactly the rev-6 delta (revision-6 line, §1 `"schema": 6`, §3 tag, §4.11 pointer, §5 line); §4.10 stays "V1–V9/R1–R13"; `diff` shows only §4.10; the diff goes into commit 1. |
| PR-4 | [SQ-26] on Q-57, P-06, K-07, FZ-07; [SQ-27] on FZ-08 and in K-04's name cell; Q-57 expectation "D.2 count per command, stale `cmd_seq` and ERR 7 excepted". |
| PR-5 | [O-7] on Q-12, Q-33 (Q-33: link-data pool full); OPEN-M5-07 Blocks = Q-12, Q-33, RL-08, H-06 (Q-06 uses the vector budget). |
| PR-6 | H-02 and H-09 [HX-RF]; H-03 re-based on a TR pair from a shared SK (M3 init, no HX), so H-03…H-06, H-08, H-10…H-13 do not inherit [HX-RF]; H-08 no longer captures H-02. G-06: stated not [HX-RF] — the vector generators keep stream-drawn route `sid`s; ADR-048 Part 3 says so. |
| PR-7 | ADR-048 Part 3 names `hx-0003` (invite, per R-60) and the cases built from its InvitationV1/URI (ids from SCHEMA-4.10 by the ref, file not available here); draw-and-discard per OPEN-M5-14 B in ADR-048, G-05, OPEN-M5-decided, WEISUNG_REF M5-2. |
| PR-8 | ADR-048 Consequences: only the SQ parts of (f)/(j) and (o)/(p) are veto-local; anything else in (a)–(l) is pinned (listed) ⇒ STOP. BRIEF §2: "except the SQ-26/27/28 parts of (f) and (j)". |
| PR-9 | ADR-048 (k) appends REF-M5 readings 5 and 6 (ERR_EXISTS on a consumption marker; `one_time` 0 kept). |
| PR-10 | T-10 withdrawn (number not reused) → H-11 `harness_transport_runs_over_in_process_streams` (duplex + chunking in-process stream, no socket). |
| PR-11 | RL-18: type-level assertion only; cargo-tree ban dropped; relay-generated ids may use another hasher (`docs/06:40`). |
| PR-12 | V-22 and V-25: "the Rust generator writes `vectors/<suite>.json`; it equals `vectors/ref/<suite>.json` as xtask step 12a compares it". |
| PR-13 | H-07 withdrawn (number not reused). The docs/07:109 restart criterion keeps a row: H-12 asserts queue re-creation and that the conversation continues, with no outbox re-send (stated as M6). BRIEF §6: "outbox and re-sending of lost cells (M6) · … receipts (M7)". |
| PR-14 | BRIEF §5: A→B handover also needs `linux-full` (Kani and fuzz steps). |
| PR-15 | CLAIMS: Excluded list names §11.1 Q rid/sid unlinkability and `akc` detectability against the operator (tests Q-01, P-05, C-11, RL-19); L11 anchored on §11.1 LINK "client anonymity" (`docs/03:705`); LO-1 marked decided. |
| PR-16 | PV-01 `proverif_link_matches_claims`, PV-02 `proverif_tr_t14_second_receive`, PV-03 "docs, no test"; FZ-09 "(existing target)". |
| PR-17 | [R5-1] dropped from Q-07; [O-14] on V-23…V-25, G-04, G-05; [O-15] on V-24; [O-16] on PV-01, X-04, X-05; legend line for SCHEMA-4.11 case labels. |
| PR-18 | `:829` → `:827` (Conventions, Q-52); F-10 range `:830-836`. |
| PR-19 | ADR-048 (m) anchor `:202`; pooled-queue sentence kept, with the reason stated. |
| PR-20 | E-4 states why the plural differs from D-04; E-6 states why rev 2.6, not D-27's rev 2.5; E-8 "(a)–(d), (f)–(p) [and (q) if adopted]". |
| PR-21 | X-07 marked [O-17]; OPEN-M5-17 added (pending; planner default as dictated). |
| PR-22 | G-01: "states with `hk_r` and `nhk_r` set; an absent key costs one dummy open"; anchor §7.4 `:440`. |
| Gap 1 | F-12 `link_client_response_value_rules_reject` (A). |
| Gap 2 | Q-60 `q_request_decoder_rules_tear_down` (B). |
| Gap 3 | RL-21 `relay_restart_identical_link_put_is_accepted` (B). |
| Gap 4 | H-13 `harness_undecryptable_cell_is_acknowledged` (C). |
| Gap 5 | RL-22 `relay_hello_to_hs1_timeout` (B, 30 s); LINK_PUT ERR 7 after frame 3 in RL-13 and ADR-048 (p). |
| Gap 6 | RL-23 `relay_config_controls_start_and_limits` (B); acceptance map "config RL-23". |
| Gap 7 | M2 canonicality properties cited; P-13 `prop_link_wire_canonical` conditional (A), decided by the table in commit 1. |
| Gap 8 | M2 frame-plaintext Kani harnesses cited; K-08 `kani_q_frame_plaintext_exact_fit` conditional (A), decided by the same table. |

Counts after: 230 rows (vector 25, unit 148, integration 12, property 12, Kani 7, fuzz 9, ct 6, PV 3, xtask 8; A 75, B 127,
C 28) + 2 conditional. No row renumbered; T-10 and H-07 withdrawn; new ids F-12, Q-60, RL-21…RL-23, H-11…H-13.
