# OPEN-M7 — decisions (reviewer Fable, 2026-10-27 19:30 UTC)

Pin: `main` = `bf550999fb2c7771153863f1da2f19adb5a677b5` (tree `86de568`); questions and alternatives: `OPEN-M7.md` (same IDs, OPEN-M7-nn).
Basis: engineering items are decided by the reviewer under the owner delegation of 2026-09-30 and are final; owner items carry the default named below (memo 2026-10-27, +24 h unless stated) and are built as that default until the owner rules.
Exception: OPEN-M7-01 (ADR-053) has **no** silent default — every [O-01] row waits for the owner's written "ADR-053 accepted" (CLAUDE.md §5).
Rows of TEST-SPEC-M7 marked [O-n] follow this table; Q-numbers continue the reviewer's series (Q80…Q126, verifier round at the end).

| ID | Decision (Qn) | Who | Note |
|---|---|---|---|
| OPEN-M7-01 | Default A (ADR-053 Proposed in commit 1; labels `wrap`, `db`, `backup` as spec rev 2.7). **No +24 h default for the construction itself**: [O-01] rows are built only after the owner writes "ADR-053 accepted" (CLAUDE.md §5). Phase A is ordered so that every non-[O-01] row comes first (A0, G7-*, schema/migrations/secure-delete with a test-only key, CT-02 structural, FO-*, FZ-*). (Q80) | owner | no default; explicit owner acceptance required |
| OPEN-M7-02 | Default A (ADR-054 Proposed, M7 scope only). +24 h default: build A. (Q81) | owner | built as default until the owner rules |
| OPEN-M7-03 | Default A (ADR-055 Proposed; A0 probe first, no `Cargo.toml` change before the probe report and ADR-055 ratification; vet records for `rusqlite`, `libsqlite3-sys`, `argon2` (+ `blake2`) as direct deps = owner (named human) — reviewer's verifier reads the deltas, owner ratifies with one sentence, Q72 precedent). If A0 shows Arti's state DB breaks under SQLCipher unification → STOP, reviewer decides between a `secmp-store`-local `libsqlite3-sys` alternative and ADR-027 fallback. (Q82) | owner | built as default until the owner rules; Q119: SQLCipher pin = 4.10.0 (bundled by `libsqlite3-sys` 0.37.0), memo point for CS-3.1 |
| OPEN-M7-04 | A (ADR-034 amendment, reviewer). `xwin-cross` excludes store-dependent crates; `windows-native` full build stays required. (Q83) | engineering |  |
| OPEN-M7-05 | A. (Q84) | engineering |  |
| OPEN-M7-06 | A: the reviewer's Doku-Agent writes `docs/reviews/M06-review.md` (acceptance record: verdict ACCEPTED BY PHASE ACCEPTANCE, pin `bf55099`, the four phase acceptances with run IDs, external rounds FINAL4/5/5b with adjudication files, the deferred list = OPEN-M7 §4 of the brief, the explicit note that no directorate review ran and why — Owner-Delegation, time; option of a later directorate review on main) and the `docs/07:133` status "merged 2026-10-27 (#9, bf55099)"; lands as **commit 0** of `m07-client-core` from `target/fable/material/M7/`. (Q85) | reviewer |  |
| OPEN-M7-07 | OQ-19: reviewer recommendation to the owner = **A** (time-based re-send with dedup by `msg_id`, §10.4 text via ADR — silent loss across a relay restart is a correctness defect of a messenger); M7 builds **B** until the owner rules; A is carried as ADR text in the memo. Both rows SE-13a/SE-13b stay dictated. (Q86) | owner | built as default until the owner rules |
| OPEN-M7-08 | A, Opus weisung in Phase B (core is the reviewer's). (Q87) | engineering |  |
| OPEN-M7-09 | docs/09 default (+24 h). (Q88) | owner | built as default until the owner rules |
| OPEN-M7-10 | docs/09 default yes; kind 2 only if ADR-054 defines its payload, else rejected at the `Api` and SE-20 runs on kind-1 16 KiB. (Q89) | owner | built as default until the owner rules |
| OPEN-M7-11 | A. (Q90) | engineering |  |
| OPEN-M7-12 | A. (Q91) | engineering |  |
| OPEN-M7-13 | A. (Q92) | engineering |  |
| OPEN-M7-14 | A; the frozen `RatchetStateV1` byte layout is unchanged (vector check G7-13 pins it). (Q93) | engineering planner note: the pinning row is G7-18 `ratchet_state_v1_layout_unchanged` (added); G7-13 in TEST-SPEC is the mutants-scope row |
| OPEN-M7-15 | A (ADR-042 amendment: `CT_STORE_SAMPLES` = 100 000, kat parameters; plus structural CT-02 and informative real-parameter medians). (Q94) | engineering |  |
| OPEN-M7-16 | A. (Q95) | engineering |  |
| OPEN-M7-17 | A (E2-02 real-time ≤ 20 min batched; E2-02v virtual twin 500 single-cell). (Q96) | engineering |  |
| OPEN-M7-18 | A (ADR-045 amendment: job `harness`, `timeout-minutes: 150`, `expect::JOB_BUDGETS` policy pin). Owner adds `harness` to the ruleset before the M7 merge (owner memo). (Q97) | engineering; ruleset owner | built as default until the owner rules |
| OPEN-M7-19 | B where a natural short form exists, else A with named killers — the executor reports which per test with times. (Q98) | engineering |  |
| OPEN-M7-20 | A (explicit filter; "Q27" is this item — reviewer's own carry-over id, now resolved). (Q99) | engineering |  |
| OPEN-M7-21 | A (`miniz_oxide` inflate-only in xtask, ADR-031 amendment; vet: xtask is not shipped — reviewer audit record allowed per docs/06 §3 for tooling? If docs/06 §3 reserves vet records to humans for all direct deps, then owner ratifies as in 03; the executor quotes the docs/06 line). (Q100) | engineering (vet record: see note) planner note: `docs/06:65` — "a `cargo vet` entry (an imported audit … or a local audit by a named human reviewer — an AI agent must not record itself as auditor)"; it makes no exception for tooling, so the record is the owner's (as 03) unless an import covers `miniz_oxide`; Q122: G7-11 moves to Phase C as (cond: the owner's `miniz_oxide` vet record has landed), asked in memo item 3 |
| OPEN-M7-22 | A. (Q101) | engineering |  |
| OPEN-M7-23 | B (not M7) unless the owner says A within +24 h. (Q102) | owner | built as default until the owner rules |
| OPEN-M7-24 | Phase B, Opus; Kani bounds never lowered. (Q103) | engineering |  |
| OPEN-M7-25 | A; `docs/01` question in the owner memo. (Q104) | engineering / owner | built as default until the owner rules |
| OPEN-M7-26 | A. (Q105) | engineering |  |
| OPEN-M7-27 | Default A (+24 h). (Q106) | owner | built as default until the owner rules — default text revised by Q125: view-once memory-only on both sides (CS-3.4 `docs/04:55`), never in the outbox; an unsent view-once is lost at restart and reported (`ViewOnceLost`) |
| OPEN-M7-28 | A (engineering reading of §7.7; `identity rotate` CLI verb as test trigger; owner informed, may veto within +24 h). (Q107) | engineering |  |
| OPEN-M7-29 | Default A (+24 h). (Q108) | owner | built as default until the owner rules |
| OPEN-M7-30 | Owner adds the `docs/01` sentence (text in the memo, from ADR-048 F-M7); code row PR-04 unaffected. (Q109) | owner | built as default until the owner rules |
| OPEN-M7-31 | A (not M7; M9). +24 h default. (Q110) | owner | built as default until the owner rules |
| OPEN-M7-32 | A. (Q111) | engineering |  |
| OPEN-M7-33 | A (not M7 code; measured retention reported). (Q112) | owner | built as default until the owner rules |
| OPEN-M7-34 | A (measure only). (Q113) | owner/engineering | built as default until the owner rules |
| OPEN-M7-35 | A. (Q114) | engineering |  |
| OPEN-M7-36 | A. (Q115) | engineering |  |
| OPEN-M7-37 | A. (Q116) | engineering |  |
| OPEN-M7-38 | A: the owner starts the `ref/` session (the ref box currently has no repo — `/work/SecMProRef` empty; the owner clones it there or the reviewer sends WEISUNG_REF to main's box with `ref/` as cwd — reviewer decides the transport at the time); store KATs marked [REF] until `vectors/store.json` exists; Phase A uses RFC 9106 Argon2id vectors + existing HKDF/CAEAD vectors. (Q117) | owner (session) | built as default until the owner rules |
| OPEN-M7-39 | Not M7 code; `Params::default()` provisional. (Q118) | owner | built as default until the owner rules |
| OPEN-M7-40 | Settled (G7-00). | — | settled |
| OPEN-M7-41 | Settled (G7-16). | — | settled |

## Verifier round (VERIFY-BRIEF-M7, 2026-10-27) — reviewer decisions Q119–Q126

| ID | Decision (Qn) | Who | Note |
|---|---|---|---|
| B1 | SQLCipher pin = **4.10.0** (the one `links = "sqlite3"` version, Arti's; `sqlcipher/sqlite3.c:108426`); ST-02 refuses < 4.10.0 and accepts 4.10.0; CS-3.1 "4.17.0" → owner memo (accept 4.10.0 as the M7 pin; moves with Arti); 4.10.0 < M0 spike 4.14.0 noted (Q119) | reviewer; CS-3.1 text owner | ADR-055 item 4, ST-02, memo item 3b |
| B2 / M8 | CT-02, ST-19, PR-03, IN-03 → [O-01], A-4 (PR-03/IN-03 wait in Phase B) (Q120) | engineering | TEST-SPEC Phase A order |
| B3 / B4 | every gate registration (`CT_TARGETS`, `CT_TARGET_SITES`, `KNOWN_SITES`, `FUZZ_TARGETS` + corpus) lands in the same commit as its target; brief §7 rule; G7-15 split per phase (15a A-4, 15b B, 15c C) (Q121) | engineering | CT-05 with CT-01 |
| B5 | G7-11 (`miniz_oxide`) → Phase C, cond: owner vet record landed; memo asks with the other vet records (Q122) | engineering; record owner | memo item 3 |
| B6 | ADR-053 item 2: unlock accepts exactly `PROFILE` (m, t, p, ver); any other value → the uniform unlock error, checked before the KDF from file bytes only (not passphrase-dependent) (Q123) | owner (inside ADR-053) | ST-06 |
| M6 / M7 | backup: own label `"SecMP-STORE/1 bwrap"` (54 labels, 0 prefix pairs), own passphrase at export, `header` = ver ‖ salt ‖ params ‖ bwrap ‖ section table with an appendix layout, plaintext magic accepted; record AD = table label ‖ column name ‖ row_key (u64 BE / len-prefixed bytes) (Q124) | owner (inside ADR-053) | ADR-053 items 5–7, Appendix |
| M10 / M12 | BK-05 → uniform `Unlock`; view-once memory-only on the sender too, loss at restart reported; OPEN-M7-27 default and memo revised (Q125) | engineering; 27 owner | BK-05, ST-17, SE-10 |
| Q132 / Q133 (A1e, 2026-10-28) | OPEN-M7-26 **B** for the one harness over the limit: `kani_commit_accept_atomic` split by store configuration into `kani_commit_accept_atomic_record_names_opk1` and `…_record_names_deleted_opk2` (no bound, unwind, stub or limit change; the runner OOMs at ≈ 15.5 GB). Q133: the cover belongs to the harness that can reach it — `kani_commit_on` returns `ok`; opk1 covers "a commit", deleted_opk2 covers "a rejected commit"; historical evidence is never edited (PR run 40688358569: cbmc 14 188 096 KiB > 14 160 156 KiB on the unsplit harness) | engineering | TEST-SPEC row K7-02 |
| Q135 (A-3b, 2026-10-29) | OPEN-M7-26 **B** applied twice, for the two harnesses at 95.1 % and 94.7 % of `KANI_CBMC_RSS_LIMIT_KIB` in the A-3 ci-full: `kani_q_frame_plaintext_exact_fit` split by decoder and context into `…_request`, `…_response_fetch`, `…_response_fetch_multi`, `tr_header_selection` split by `k` into `…_k0_2` (`k ≤ 2`) and `…_k3_4` (`3 ≤ k ≤ 4`), and, `…_k3_4` alone at 90.1 %, the latter into `…_k3` and `…_k4` (the dictated second step); no bound, unwind, stub, `frame_len()` or limit change; `KANI_HARNESSES` 51; TEST-SPEC-M7 row K7-03. |
| OPEN-M7-03 addendum, Q129 (2026-10-28) | ADR-055 is effective as the memo default of 2026-10-27 item 3 (+24 h = 2026-10-28 19:08 UTC; OPEN-M7-03 default A). The G7-02 expectation is re-dictated for A-2 only: the vet records of the direct dependencies are **provisional** (Q72 precedent, tokio/ADR-051 Am. 5) — `who` = "Claude Sonnet 5.5 (implementer) + reviewer's verifier; owner ratification pending (Q129)", notes name the actual reading; the owner's ratification sentence replaces `who` before the M7 close. ADR-053 is accepted by the owner (Q127a), A-4 follows A-3. | owner (ratification) | G7-02 |
| M1–M5, M9, M11, N1–N5 | applied as proposed: G7-00 also re-dictates `cooldown_covers_m6_lock`; red from 2026-10-31 00:00 UTC; G7-01 per `expect.rs:35-66`; A-1 order (edges only with their crates, store under mutants/coverage only with code); A0 incl. `fuzz/Cargo.lock` + sanitizer build; FO-01a/FO-02 → Phase C; memo adds OPEN-M7-21, -28, -34; cond rows G7-19 (`docs.rs:287-290`) and G7-20 (`gates.rs:7036`) tied to owner actions; `argon2` deps named; G7-07 names `dispatch-harness` and `docs/06:95-108`; module paths for all rows; CL-* in an integration binary; ST-01 reads after the first query (Q126) | engineering | — |
| Q136 (2026-10-29) | Owner delegated the ratification of the M7 vet records to the reviewer (owner chat 2026-10-29 08:20 UTC) on the reviewer's condition of a verifier reading of the compiled rusqlite modules (done, docs/reviews/M07-evidence/vet-rusqlite-0.39.0-audit.md). Ratified: rusqlite 0.39.0 (certify), argon2 0.6.0, blake2 0.11.0, password-hash 0.6.1, phc 0.6.1 (publisher trust). | owner → reviewer | G7-02 |
