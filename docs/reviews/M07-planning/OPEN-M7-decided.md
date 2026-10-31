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
| Q137 / Q138 (A-3d/A-3e, 2026-10-29) | The unwind of a harness split by `k` follows its `k`: `max(k_max + 2, TR_SKIPPED_KEYS + 1)` — `tr_header_selection_k0_2` 5, `…_k3` 5, `…_k4` 6 (the original bound); unwinding assertions on. `…_k4` is the one documented exception above the 90 % container threshold (exception Q138: `tr_header_selection_k4` 94.0 % container (ci-full) / 96.3 % alone; CI figure from the PR run on `92b4404` to be recorded; the RSS guard trips above 100 % (`gates.rs:2550`); K7-03b (heap-free harness) is pulled forward if CI is red or above 95 %); Phase B row K7-03b rewrites the three without the heap. Lifted by K7-03b (`b7d7ee6`), 7.4 % (alone; `_k0_2` 5.8 %, `_k3` 5.8 %). |
| OPEN-M7-03 addendum, Q129 (2026-10-28) | ADR-055 is effective as the memo default of 2026-10-27 item 3 (+24 h = 2026-10-28 19:08 UTC; OPEN-M7-03 default A). The G7-02 expectation is re-dictated for A-2 only: the vet records of the direct dependencies are **provisional** (Q72 precedent, tokio/ADR-051 Am. 5) — `who` = "Claude Sonnet 5.5 (implementer) + reviewer's verifier; owner ratification pending (Q129)", notes name the actual reading; the owner's ratification sentence replaces `who` before the M7 close. ADR-053 is accepted by the owner (Q127a), A-4 follows A-3. | owner (ratification) | G7-02 |
| M1–M5, M9, M11, N1–N5 | applied as proposed: G7-00 also re-dictates `cooldown_covers_m6_lock`; red from 2026-10-31 00:00 UTC; G7-01 per `expect.rs:35-66`; A-1 order (edges only with their crates, store under mutants/coverage only with code); A0 incl. `fuzz/Cargo.lock` + sanitizer build; FO-01a/FO-02 → Phase C; memo adds OPEN-M7-21, -28, -34; cond rows G7-19 (`docs.rs:287-290`) and G7-20 (`gates.rs:7036`) tied to owner actions; `argon2` deps named; G7-07 names `dispatch-harness` and `docs/06:95-108`; module paths for all rows; CL-* in an integration binary; ST-01 reads after the first query (Q126) | engineering | — |
| Q136 (2026-10-29) | Owner delegated the ratification of the M7 vet records to the reviewer (owner chat 2026-10-29 08:20 UTC) on the reviewer's condition of a verifier reading of the compiled rusqlite modules (done, docs/reviews/M07-evidence/vet-rusqlite-0.39.0-audit.md). Ratified: rusqlite 0.39.0 (certify), argon2 0.6.0, blake2 0.11.0, password-hash 0.6.1, phc 0.6.1 (publisher trust). | owner → reviewer | G7-02 |
| Q127a (2026-10-28) | owner: ADR-053 accepted — „ist akzeptiert … arbeite voll autonom" (owner chat 2026-10-28, Q127a). |
| Q139 (reviewer, 2026-10-29) | Sealed columns (ADR-053 item 5): `identity.secret`, `prekeys.secret`, `sessions.data`, `sessions.skey`, `outbox.payload`, `invitations.record`, `relays.access_key` (CS-3.3 "IKS, prekeys, ratchet states, outbox plaintext" + the invitation `link_key` and the relay access key); `messages` stays inside SQLCipher only. |
| Q140 (2026-10-29) | **open — reviewer: which CT-01 form is gated** (the informative post-KDF target `store_unwrap_reject_post_kdf` is added beside the gated `store_unlock_reject`, A-4 §4). |
| Q141 (reviewer, 2026-10-29) | Cloud folders (OPEN-M7-37 A "a component in {…}"): a `const` of path components matched case-insensitively and equal — `OneDrive`, `Dropbox`, `Google Drive`, `GoogleDrive`, `iCloudDrive`, `iCloud Drive`, `Mobile Documents`, `Nextcloud`, `ownCloud`, `pCloud`, `MEGA`, `Box`. |
| Q142 (reviewer, 2026-10-29) | `contacts::STATE_REINVITE_REQUIRED = 1`. |
| Q143 (reviewer, 2026-10-29) | `contacts` gains `profile BLOB` (schema V1 in place; `local_name` = `display_name`); `identity.secret` plaintext = the 97-B identity section; backup `ts` = `ts_ms`. |
| Q144 (2026-10-29) | ADR-053 Amendment 1 (composite row_key encoding) accepted by the owner in the owner chat 2026-10-29 ≈17:58 UTC ("ich akzeptiere deinen vorschlag"); A-4 §3 built it as Proposed, now Accepted — no code change. | owner | ST-11, ST-12 |
| Q175 (reviewer, 2026-10-30) | A `sessions` skipped entry shorter than `SKIPPED_KEY_LEN` (36 B) is malformed: `insert_skipped` returns the uniform `Error::Unavailable` and writes nothing (no `unwrap_or(entry)`); supersedes D23; the A-3 test `session_rows_round_trip` is re-dictated to entries of at least 36 B. | reviewer | A4-1-09 |
| Q145 (2026-10-29) | Phase B = 72 rows (71 built; SE-13a cond.). K7-03b (Q138) is the 72nd; BRIEF_M7.md stays as written (historical); `M07-report.md` §1 corrected to 178 rows (A 66, B 72, C 40). | reviewer | NOTES-B (a) |
| Q146 | Order: WEISUNG M7-B-SC (Opus, own session M7-B-SC) first; BRIEF M7-B (Sonnet, new session M7-B) B-1…B-3, return "B-3 built @"; WEISUNG M7-B-4 (continuation of M7-B) B-4…B-7, return "Phase B closed @". | engineering | |
| Q147 | Proto additions in B-SC §0 (Opus): `issue_invitation_on` with explicit pool-queue seeds (`issue_invitation` byte-for-byte; `cargo xtask vectors` unchanged); typed zeroizing seed export/import for `SpkGeneration`/`OpkSecrets`/`InvitationRecord` (no wire structure, no serde); `Responder::accept_classified` (RT-1), `accept` a thin wrapper, responder Kani harnesses re-measured (STOP > 90 %); KeyChange signing in product under the §7.6/§7.7 label (no new label; oracle `tr/tests.rs:2014`); K_id/SK accessors `cfg(feature = "kat")` only; own tests, mutants; Miri > 60 s named (MIRI_SKIP accepted per test). | engineering | N0 |
| Q148 | Retention = newest 24 of (retained ∪ fetched) \ spent, by `cell_id`. | engineering | N1 |
| Q149 | `invitations.retained BLOB` sealed, V1 in place, AD per ADR-053 Am. 1; committed with the deciding commit before the ack. | engineering | N2 |
| Q150 | Initiator handshake cells = `sessions` part 4 `HANDSHAKE` (sealed `sessions.data`), deleted at the first decrypted reply. | engineering | N3 |
| Q151 | Seal `contacts.routes`, `contacts.queues`; add sealed `relays.pool BLOB` (V1 in place); ST-12 unchanged; extra store test `schema::tests::capability_columns_are_sealed`. | engineering | N4 |
| Q152 | `git mv scheduler/conversation.rs → sessions/actor.rs` in its own commit; test names unchanged; `docs/mutants-accepted.md` rows of `conversation.rs` re-pinned in that commit, if any (none at `92b4404`). | engineering | N5 |
| Q153 | AP-04 re-dictated (importers {`scheduler::core`, `scheduler::run`, `kani_proofs`}; 11 types ∪ pinned plumbing allowlist); D-B2 "no `net` module". | engineering | N6 |
| Q154 | IN-12 re-dictated (refined by V-10/V-22, N-02): Expected positional `Expired, Unsupported, Mismatch, Invalid; Ok`; check order kind byte → `Unsupported`; decode → `Invalid`; expiry → `Expired`; inviter fp (`ct_eq`) → `Mismatch`; proto `Rejected` → `Invalid`; no second decoder, no separate `spk_expiry` step; from the invitation and the opened link data, local only. | engineering | N7 |
| Q155 | B leaves `two-clients`; IN-17 asserts no set-up link and zero overruns; C-T3 deletes the scripted path. | engineering | N8 |
| Q156 | AP-03: items 1–5 verbatim + `docs/03:662` sentence (Balanced/direct) + `docs/03:231` sentence (direct). | engineering | N9 |
| Q157 | SC-10 = `xtask::testscan::kc5_calls_extracted` (source scan, the row's assertion kept); no K-C5 rename; D-B3. | engineering | N10 |
| Q158 | PR-06: the scanner accepts `label ‖ fp_peer ‖ fp_scanner`; swapped = `label ‖ fp_scanner ‖ fp_peer`. | engineering | N11 |
| Q159 | `T_RS` = max(24 h, 2·QUEUE_CAPACITY·P_q), named constant citing OPEN-M7-07 (not normative); once per `msg_id`; verified contacts with receipts only; D-B4. | engineering | N12 |
| Q160 | SE-19 latency injected in virtual time on the worker's commit completion. | engineering | N13 |
| Q161 | SE-02 "last 128 cells" = outbox rows of the old queue with `cell_id` > newest − 128 (delivered included). | engineering | N18 |
| Q162 | Local Kani step > 135 min = STOP; no budget change in advance. | engineering | N19 |
| Q163 | IN-11 retirement: U[1 min, 60 min] and an empty `FETCH` first. | engineering | N20 |
| Q164 | `rotate_identity` retires every unconsumed invitation (`Event::InvitationRetired { id, reason: IdentityRotated }`, `QUEUE_DEL` on the IN-11 schedule); a handshake on a retired invitation is dropped silently; D-B5; owner memo line. | reviewer; owner informed | N24, SE-09 |
| Q165 | SE-16: entry once the session's ratchet state exists and is durable. | engineering | N26 |
| Q166 | AP-05: kat-random 64-bit row-id offset in that run. | engineering | N29 |
| Q167 | SC-03 runs six modules (+ `m6_sim_faults`, `m6_props`); SIM-02 "≤ 6 cells" assertion added with SC-01. | engineering | N37 |
| Q168 | SC-01 re-dictated: Strict silent 45 / constant-rate 66 periods; Balanced ≥ min(F_M, backlog) − 1 per response, 21 / 24 slots. | engineering | N38 |
| Q169 | Anchors: ADR-044 (f) = `docs/08:422`; F_M = `docs/03:662`. | engineering | N39 |
| Q170 | Status texts: only ADR-054 → Accepted (owner default) in commit 0; `docs/04:45` CS-2.2 note closed in IN-21's commit; `docs/09` untouched. SE-19 activity set + IN-17 zero-overrun clause dictated (from NOTES-B (h)). | reviewer / owner default | N40 |
| Q171 (V-02) | PC-12 (`testscan.rs:516-527`) re-dictated in the SE-18 `git mv` commit: the known-file entry `scheduler/conversation.rs` → `sessions/actor.rs`, which the scan also reads (scope `scheduler/**` + `sessions/actor.rs`); the test edit is sanctioned; the other path updates are listed in that commit (`core/mod.rs:314-315, :2034`, `persist.rs:816, :831`, `scheduler/mod.rs:3, :29`, testkit/fuzz imports incl. `two_clients/rand.rs:7`, `two_clients/run.rs:26`). | engineering | E16 |
| Q172 (V-05, V-19) | The retention function is `crate::retention` (top level, no store dependency, Kani-built), heap-free: `retain(retained: &[u64], fetched: &[u64], spent: &[u64], out: &mut [u64; 24]) -> usize`; K7-01 harness on it, no `Vec` in the Kani path. | engineering | K7-01, FZ-04 |
| Q173 (V-20) | No resident prekey secret beyond one operation: `MemoryPrekeyStore` is a per-operation view built from the sealed store and zeroized/dropped after it; IN-21's `link_key` rule (memory only during the step) is the stricter one and wins. | engineering | PR-02, IN-21 |
| Q174 (reviewer, 2026-10-30) | ci-full evidence files are committed in the A-3b summary form; a file > 2 MiB is reduced, never allowlisted (ADR-052). | engineering | evidence rule |
| Q176 (EXT1-1) | EXT1-1 minor; F9b recorded in A-4f; fix in Phase B (B-4, SE-21). | reviewer | F9b |
| Q177 (EXT1-3) | `retention_days` has one typed codec: backup wire = u32 big-endian (4 bytes), SQLite = INTEGER; export reads INTEGER (`u32::try_from` failing → `Unavailable`), decode rejects `val_len ≠ 4` (`Unlock`), import writes INTEGER; `Store::retention` unchanged; BK-01 fixture re-dictated to INTEGER 30, wire bytes unchanged; ADR-053 Am. 2 Proposed. | reviewer | BK-01 |
| Q178 (EXT1-2) | `wrap::create` holds `<dir>/lock` from before the existence check to the publish (`rename`); per-call `wrap.<pid>.<n>.tmp`; no foreign-tmp removal; a stale tmp from a crash is left in place. Reopens A4-1-02. | reviewer | A4-1-02 |
| Q179 (EXT1-4) | (a) import rejects a settings key outside `BACKUP_SETTINGS_KEYS` (`Unlock`) before any write; (b) the empty-profile rule counts `settings` too: nine tables. Residual of A4-1-04. | reviewer | A4-1-04, A4-1-06 |
| Q180 (EXT1-5) | `store_record_open` even mode accepts an authentic record (`Ok`, or the uniform `Err(Unavailable)`); one authentic seed added to the committed corpus. | reviewer | FZ-02 |
| Q181 (A-4f2) | A repeated settings key in a backup section is refused (`Unlock`) before any write: canonical decode (§1.8); fixed seen-set over `BACKUP_SETTINGS_KEYS`. | reviewer | BK-01 |
| Q182 (B-SC2) | `RecvLedger::take` hands a cell to the cell source only when the ledger can record it (`Received::can_record`; full: `note_full`, the pass stops); persist-before-ack holds under a hostile relay (F1, Major of B-SC). | reviewer | SC-01, SC-02 |
| Q183 (B-SC2, amended by B-SC2b) | SC-09 re-dictated over the activity inputs that reach the core (ready pass, written-report pass, commits pending); `pure::fetch_due`, `pure::note_sent` extracted; the SC-10 scan pins `prepare_link → fetch_due → fetch_lead_deadline`. | reviewer | SC-09, SC-10 |
| Q184 (B-SC2) | SC-08 gains the hostile-relay class (arbitrary ids ≤ 7 per response, the handed-id oracle); kept at ≤ 90 % RSS alone. | reviewer | SC-08 |
| Q185 (B-SC2) | FZ-04 `scheduler_event_sequence` drives the deferred path (real cells, hostile response modes, late commits, frame reports) with the §1.7 oracle. | reviewer | FZ-04 |
| Q186 (B-SC2) | Q44 entries, one in-diff mutants run, report corrections. | reviewer | G7-09 |
