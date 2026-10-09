# Review — M05 SecMP-LINK + SecMP-Q + relay core + in-process harness

Reviewer: Fable (planner session) with an Opus directorate: planning cells A1–A3, binding gate, eight lenses L1–L8, twelve verifiers V1–V12, red team (F1/RT), reconsolidation (F3) · Date: 2026-10-09 · Branch `m05-link` → `main`, draft PR #7 · Report: `docs/reviews/M05-report.md` (Phases A/B/C, 558 lines)
Reviewed code: `3b29ca86ccbea6f840eca043c5c23456eca1c1c3` (tree `4ded5a31…`, parent `fb2d651` = code head; the pin adds the report commit; 2026-10-09T04:11:20Z). Base `main` = `a229dbf` = M4 squash, an ancestor of the pin; `m05-link` = `origin/m05-link` = pin, no drift. Diff base..pin: 253 files, +62204/−626; the frozen diff is not empty (docs/01, docs/03, `formal/CLAIMS.md` +164, `vectors/SCHEMA-4.10-hx.md`, new `SCHEMA-4.11-link.md`, `hx.json`/`ref/hx.json` re-freeze rev 2.6, new `link.json`/`ref/link.json`) and is covered by ADR-048 (rev 2.6, owner default effective 2026-10-04 20:45 UTC), ADR-049 (accepted by the reviewer 2026-10-08) and ADR-050 (§E).
Verdict: **APPROVED WITH CONDITIONS — C-1…C-13 before merge; no blocker; two CONFIRMED majors (R-105, R-106: unauthenticated relay crash with total loss of the RAM state, reproduced by V1). Owner approvals prepared (§D, default 24 h); follow-ups F-1…F-17 scheduled (§H).**
No CLAUDE.md §1 invariant is broken: nothing leaks, dying is fail-closed, §1.7 is client-side, and re-creation after a restart is the designed path proven by H-12 (RT §2). The GO is bound to: a green PR run on the fix head, the Linux ct report, a non-vacuous mutants verdict (6 → 0 unaccepted survivors, matcher keyed on `path:line`), green `ref/` tests, and the reviewer's delta verification `3b29ca8..<fix head>`.

All `file:line` references in this review are `@3b29ca8` unless stated otherwise.

**CI at the pin.** PR run `37882708499` (headSha = pin, completed, conclusion success): 16/16 jobs success. The artefacts carry the merge ref `1b4820e4…`; `origin/main` = `a229dbf` is the base of the branch, so the merge is a fast-forward and its tree is the pin's tree (binding-notes EV-1, `M05-evidence/review-binding.txt`).

| Job | Minutes | Result |
|---|---|---|
| `linux-fast` | 33 | success (nextest 718 tests PASS) |
| `linux-full` | 219 | success (`ci-full: PASS`) |
| `ct` | 138 | success, `run_verdict` PASS |
| `proverif-link` | 20 | success, 9/9 files |
| `proverif-hx` | 9 | success |
| `windows-native` | 40 | success |
| `xwin-cross` | 3 | success |
| `mutants-shard (0…7)` | 40–76 | success (shards 0–6 241 mutants each, shard 7 240) |
| `mutants` (merge) | 1 | success, 1927 mutants |

**How this was reviewed.**
- Source: the `git archive` of the pin (2734 files = the `git ls-tree -r` count). Only this tree was read; no worktree, no later head.
- Directorate: planning A1 (obligation matrix), A2 (threat/consistency map, hypotheses H-1…H-18), A3 (evidence plan, EV-1…EV-12); binding gate; lenses L1 spec, L2 threat model, L3 constant time, L4 memory, L5 supply chain/CI, L6 tests, L7 ProVerif ↔ code, L8 relay/DoS; verifiers V1–V12; red team (RT); reconsolidation (F3) into a register of 58 rows R-105…R-162 (2 major, 15 minor, 16 nit, 25 note) plus RT-01…RT-03 (RT-01 merged into R-120; RT-02, RT-03 are R-163, R-164).
- Independent Python recomputation (`python3 -I`, hashlib/hmac and pyca `cryptography`): 100 values of `vectors/link.json` (L1: handshake link-0001…0004, QUEUE_NEW 0006, SEND 0007, FETCH 0012, LINK_PUT 0025, replay 0050, hx-0003 `inv_sid`) and 38 values (RT: QUEUE_DEL 0024, FETCH_MULTI 0019, budget 524 800 / 12 488, record sizes HELLO 9, RelayInfo 1744, HS1 2856, HS2 1156) — **0 mismatch** (`M05-evidence/review-l1-recompute.txt`, `review-rt-recompute.txt`).
- The CI ct JSON of the run re-derived with `cargo xtask ct-check` (PASS, 26 targets of `expect::CT_TARGETS`, `xtask/src/expect.rs:123-150`; `M05-evidence/review-v12-ct-check.txt`).
- V1 reproduction of the thread/EMFILE crash (debug build, toolchain 1.98.1, limits set with `prlimit`; `M05-evidence/review-v1-repro.txt`).
- The ProVerif gate gap reproduced with a unit fixture in a scratch copy (V7: an edited lQKey log passes the gate).

**Review evidence committed with this review** (`docs/reviews/M05-evidence/`):

| File | Content |
|---|---|
| `review-l1-recompute.txt` | `python3 -I calc/L1_link.py vectors/link.json`: script header + output `OK 91 MISMATCH 0`, `after hx: OK 100 MISMATCH 0` |
| `review-rt-recompute.txt` | `python3 -I calc/RT_vectors.py vectors/link.json`: script header + 38 checks, `OK 38 MISMATCH 0` |
| `review-v1-repro.txt` | V1 reproduction transcript, `err01.txt` (spawn panic, EAGAIN), `err02.txt` (`i/o error`, exit 1), V1 verdicts |
| `review-v12-ct-check.txt` | `cargo xtask ct-check` on the CI ct JSON (PASS), run header, per-target table, controls, `caead_derive` analysis |
| `review-binding.txt` | binding-gate notes (EV-1, survivors per shard, `linux-full` step summary) |

**Limits of evidence.**
- ProVerif was not run locally; the verdicts rest on the model hashes, which equal the evidence logs and the CI run.
- Kani, Miri and Windows only through the run.
- The lock hold time of R-109 is estimated (1.6–3.8 ms per FETCH_MULTI), not measured; the Tor timing of R-108's observation channel is not measured.
- R-105 was reproduced with an address-space limit as a stand-in for the cgroup pids limit (same errno EAGAIN); the literal `TasksMax=512` run was not performed. R-107 was not reproduced live (it needs a full HELLO/HS1 client): deterministic reading.
- The ct JSON records no head or merge sha; its binding to the pin rests on the artefact name plus the tree argument above (F-17). `bench_sha256` hashes the bench executable and cannot be checked without a reproducible bench build.
- hx-0031…0037 of the rev-2.6 `hx.json` re-freeze were not recomputed independently (RT-01, R-120).

## A. Scope and acceptance

| Criterion (`07` M5) | Evidence checked | Result |
|---|---|---|
| Two clients create queues (pool) | H-01 | **met** |
| 1 000 cells each way | H-03 `harness_exchange_1000_cells_each_way`: exact ordered lists a0…a999 / b0…b999, 0 discarded, final FETCH empty, `committed_ack` = 1000 | **met** |
| Relay evicts at capacity and reports ids | Q-11, H-04, K-06; eviction reports the oldest, `cell_id` from 1 (`crates/secmp-relay/src/cells.rs:84-106`) | **met** |
| Sweeper expires by bucket | RL-04…RL-06, H-05; `crates/secmp-relay/src/clock.rs:21-43` (`now > anchor + T`, OPEN-M5-05 B) | **met**; boundary rule only in OPEN-M5-decided (R-128, owner §D 1(b)) |
| Memory budget refuses new queues at the limit | Q-06, RL-08, H-06 | **met**; "worst case" wording (R-129, F-9) |
| Restart → `ERR_NOQUEUE` → identical queues → continue, no new invitation | H-12, RL-01, RL-21, Q-20, Q-31 | **partly**: the chain is met; "no mk reused" is not asserted (R-115, **C-8**) |
| All responses `FRAME_SIZE` | Q-57, H-08, V-16, `assert_d2_shape` | **met** |
| Error and success frames byte-level indistinguishable | Q-57, P-09, V-16, H-08 | **met by composition** (no single paired test) |
| Fuzz target for the executor | FZ-07 `relay_executor` (CI fuzz PASS, 29 targets) | **met**; depth weak (R-127, F-8) |
| Relay unit tests for every command | Q-01…Q-46 (9 opcodes incl. errors) | **met**; over-rate SKEY untested (R-139, **C-10**) |
| `FETCH` idempotence and cumulative ack | Q-14, Q-15, Q-16, V-09, H-03, H-13 | **met** |

| Review focus (`07` M5) | Evidence checked | Result |
|---|---|---|
| Strict counters | F-03, F-06, F-08, K-02, K-03; strict +1 by nonce = expected counter with `checked_add` (`crates/secmp-proto/src/link/frame.rs:48-50,192-199`); a failed open changes no counter (`crates/secmp-relay/src/executor.rs:217-239`) | **met** |
| `sess_id` in command signatures | Q-55; D.6 recomputed by L1; `crates/secmp-proto/src/wire/signed.rs:20-140` binds label ‖ `sess_id` ‖ u32be `cmd_seq` ‖ D.2 fields | **met** |
| One-time consumption atomic | under the global lock with a marker (`crates/secmp-relay/src/exec.rs:339-386`); Q-42 (probabilistic) | **met** |
| Owner status non-consuming | Q-40 | **met** |
| Eviction reporting | Q-11, H-04, K-06 | **met** |
| Zeroize on delete | stored `CellBuf`/`BlobBuf` wiped on every delete path (RL-10); transient copies on the response and upload paths freed unwiped (R-111) | **partly**; **C-4** |
| Hour buckets only | `clock.rs:21-43`; sweep before every command (`crates/secmp-relay/src/relay.rs:136-148`); H-12 (A2) REFUTED by V11 | **met** |
| `RelayInfo` never cached by the client | test C-13 (TEST-SPEC); fresh `AwaitRelayInfo` per `Session::connect` (`crates/secmp-transport/src/session.rs:82-102`) | **met** |

| Gate (run `37882708499`) | Evidence checked | Result |
|---|---|---|
| `linux-full` 219 min | kat PASS 1543 s (crypto, proto, relay, testkit; link suite included; proptest seed 37882708499); fuzz PASS 3579 s (29 targets × 120 s, `relay_executor` and `relay_link_session` included); coverage PASS 499 s; miri PASS 2954 s (sys-mem, sys-desktop, crypto, proto); kani PASS 3918 s, 33/33 (proto + relay); `12a ref-vectors` 12 frozen suites (969 cases) byte-identical | **PASS** |
| Coverage | crypto 99.4 % (2523/2539), proto 97.7 % (6585/6741), relay 97.6 % (2175/2229), testkit 94.3 % (607/644), transport 89.7 % (546/609), sys-mem 95.3 %; equal to the local `fb2d651` numbers (EV-3) | **PASS** |
| `ct` 138 min | `run_verdict` PASS; CT-01…CT-06 max\|t\| ≤ 2.79, A/A ≤ 2.66; `caead_derive` SUB_FLOOR_SHIFT at p95 (t 45.45/45.88, Δ 0.099/0.089 floors), admissible; positive control `control_variable_time_compare` detected (t −21801.2 at p75); the "FAIL p90 122.6/122.5" is `min_leak_control`, which must decide FAIL (ADR-041 Am. 3) — not the positive control (REPORT Block B misattributes it; **C-13**) | **PASS** (V12) |
| `proverif-link` | 9/9 files, every RESULT as CLAIMS; lBoth 1139.1 s of the 1800 s cap (63 %, R-152) | **PASS** |
| `mutants` | 1927 mutants; secmp-crypto caught 171 / missed 1 / unviable 107 of 279 (61.3 % caught, 38.4 % unviable: WARNING > 35 %, ADR-047 Am. 2; R-148); secmp-proto 853/3/350 of 1206; secmp-relay 318/2/122 of 442; 6 survivors = 5 rows of `docs/mutants-accepted.md` (binding-notes) | **PASS** at the pin; the gate is weaker than TEST-SPEC-M5 (i) and two rows are not accepted (R-114, **C-7**) |
| `windows-native`, `linux-fast`, `xwin-cross`, `proverif-hx` | job table above | **PASS** |
| Report checklist "ci green" (unchecked in the report) | done by run `37882708499`; to be ticked in the fix report | §E |

**ct targets of the run, re-derived (V12; `M05-evidence/review-v12-ct-check.txt`).** Host AMD EPYC 7763 (Azure VM), rdtscp, tick 0.408928 ns, floor 24.5 ticks (10 ns); thresholds pass 4.5, A/A max 4.5, 1 000 000 samples; every target k_initial = k, no re-batch; all A/A max\|t\| ≤ 2.672.

| Target | Verdict | max\|t\| first / second | Δ at that crop (floors) |
|---|---|---|---|
| `link_hs1_reject_mac1` (CT-01) | PASS | 1.31 @raw / 0.74 @p50 | raw −1.99 / −0.58 |
| `link_hs2_reject_mac2` (CT-02) | PASS | 0.74 / 0.86 | p99 1.22 / 1.24 |
| `link_frame_open_reject` (CT-03) | PASS | 0.82 / 1.46 @p99 | ≤ 0.11 |
| `q_queue_new_reject_token` (CT-04) | PASS | 2.79 / 0.57 | ≤ 0.04 |
| `tr_decrypt_trial_open_position` (CT-05, R-59) | PASS | 1.26 / 1.11 | ≤ 0.10 |
| `link_same_content_control` (CT-06) | PASS | 0.97 / 1.40 | 0.39 |
| `caead_derive` | SUB_FLOOR_SHIFT @p95 | 55.28 @p75 / 46.28 @p90; @p95 t 45.45 / 45.88 | 0.099 / 0.089 (largest 0.104 @p99); FAIL not possible |
| `control_variable_time_compare` (positive control) | detected | −21801.2 @p75 | −852.8 |
| `min_leak_control` (sensitivity, ADR-041 Am. 3) | FAIL as required, reached | t 5986.87 / 5806.94 @p90 | 122.64 / 122.54 |
| `hx_same_content_control`, `same_content_control`, `aa_prime_control` | PASS | 1.43 / 1.16; 3.91 / 0.63; 12.83 @p95 / 3.78 (first-only excursion) | — |

No target meets V12's fragility criterion; two unreproduced single-measurement excursions are noted (`caead_aead_reject` t −14.84 at p95, `aa_prime_control` 12.83 at p95, both Δ ≤ 0.03 floor).

**Planning items — disposition (register §4–§6).**

| Item | Disposition | Row |
|---|---|---|
| H-1 listener HELLO bucket | CONFIRMED by V2 (+ L2-01, L8-04) | R-108 |
| H-2 expired kid | REFUTED by V9-02 | — |
| H-3 key-less invitees and per-user access keys | Decided: OPEN-M5-01 A is the owner default (effective 2026-10-04 20:45 UTC); docs/01:51 holds for key holders; not verified by a V-cell | R-118 (b) |
| H-4 over-rate SKEY | Consistent reading, test gap (V9-01) | R-139 |
| H-5 foreign `sid` on QUEUE_NEW | CONFIRMED by V9-03 (undeclared, unreachable) | R-138 |
| H-6 TEST-SPEC row existence | Resolved by L6 (scripted check) + CI kat PASS incl. the relay suite | — |
| H-7 `LINK_MAX_FRAMES` | REFUTED by V11 | — |
| H-8 expiry boundary | CONFIRMED by V11 (doc gap, nit) | R-128 |
| H-9 state before commit | REFUTED by V11 | — |
| H-10 FETCH_MULTI acked-not-reported | Spec-conformant (V10-1); test gap | R-140 |
| H-11 lock amplification | CONFIRMED by V3 | R-109 |
| H-12 ms timestamps | REFUTED by V11 | — |
| H-13 budget undercount | CONFIRMED (nit); 129-cell part REFUTED by V3 | R-129 |
| H-14 `evicted`/CELLR ids | OK_SEND half CONFIRMED, CELLR half REFUTED (V10-2) | R-122 |
| H-15 LO-5…LO-7 and bounds | Resolved by L7: no trivialisation; exclusion list incomplete | R-118, R-149 |
| H-16 harness `Box::leak` | Resolved: test-only; H-12 runs against the new instance | R-162 |
| H-17 identical QUEUE_NEW in drain | CONFIRMED by V9-04 (test gap + undecided reading) | R-119 |
| H-18 SCHEMA anchors, RR-16 gap | Recorded as editorial nit | R-137 |
| EV-1 merge-ref tree | Resolved (binding-notes: fast-forward of `a229dbf`) | — |
| EV-2 / EV-3 step summaries, coverage | Resolved (binding-notes: CI = local `fb2d651` numbers) | — |
| EV-4 ADR-042 M5-C line | Reviewer acceptance (§E) | R-154 |
| EV-5 fuzz depth | Verified by V6 (nit) | R-127 |
| EV-6 `ref/` regeneration | CONFIRMED (F3, RT-01) | R-120 |
| EV-7 mutants survivors | Resolved (binding-notes: 6 survivors per shard) | R-114 |
| EV-8 crypto unviable breakdown | Report line owed | R-148 |
| EV-9 K-01 `assume` | CONFIRMED (F3) | R-121 |
| EV-10 CI ct JSON | Resolved by V12; evidence commit owed | R-125 |
| EV-11 `#[ignore]` scan / EV-12 workflow texts | Recorded | R-155 / R-133 |
| A1 S9-12 per-queue keys never linked to the IKS | Structural at M5 (raw 32-B seeds, no IKS type in relay/transport/testkit); no test | R-143 (F-14) |
| A1 S9-30 no double-spend list in v1 | Met by construction (no token store in `crates/secmp-relay/src`, V3) | consequence R-110 |
| A1 K5-4 X25519 all-zero check in hybrid encaps | Met (`hybrid_kem.rs:100-101,182-183` → `x25519.rs:64-67`; LINK at `link/client.rs:111`, `link/relay.rs:223`; tests C-19, RH-06) | — |
| A1 K5-6 decapsulation keys stored as seeds | Met (key file seeds, 0600); the report should state it | — |
| A1 FM-LEAK Windows fake bench | Still open | R-156, R-164 |

## B. Spec conformance — verified by reading the code

R-nn = register row (§C). Spec = docs/03 rev 2.6.

- **Vectors and independent recomputation.** `vectors/link.json` = `vectors/ref/link.json`, sha256 `dd77bb7c…` = the hash ADR-048 pins, 86 cases. L1 recomputed 100 values written from docs/03 §3.2, §8, §9, App. A/B/D and SCHEMA §2 only: RelayInfoV1 1741 B and its deterministic Ed25519 signature over "SecMP-LINK/1 relayinfo" ‖ 1677 B, both HybridKEM combiners (V = "SecMP-HybridKEM-1024/1" for `ss1`, "SecMP-HybridKEM-768/1" for `ss2`), `h0`/`ck1`/`mac1`, `h1`/`ck2`/`mac2`, the 80-B expand split 32/32/16 into `k_c2r`/`k_r2c`/`sess_id`, sealed 4352-B frames, D.6 signatures, LINK_PUT's three request frames, and the replay case. RT added QUEUE_DEL (link-0024), FETCH_MULTI (link-0019, arrival order confirmed), the App. B budget and the record sizes. 0 mismatch in both. Positive (RT-01): `link_cases.link_cases()` reproduces `vectors/ref/link.json` byte-exactly; only the generator wiring is missing (R-120).
- **LINK codec and handshake (`crates/secmp-proto/src/link/`, `wire/`).**
  - All App. A labels byte-exact (`crates/secmp-crypto/src/label.rs:167-205`); HMAC/HKDF prepend the label raw, no length prefix (`mac.rs:49-56`, `kdf.rs:47-56`).
  - §8.3 order line by line (`link/handshake.rs:1-99` (key schedule), `link/relay.rs:191-260`, `link/client.rs:176-230`); the relay compares `mac1` with `ct_eq` before any draw (`link/relay.rs:213-223`); the client verifies `mac2` with `hmac_sha256_verify` before deriving keys (`link/client.rs:183-189`) and draws in OPEN-1 order (`client.rs:109-111`).
  - RelayInfo checks: signature (strict) → `relay_fp` (ct) → `valid_until ≥ now` → `≤ now + 5 184 000` (exactly 60 d accepted) → `akc` only with an access key (`client.rs:75-102`); kid validity checked before decaps in production (`crates/secmp-relay/src/conn.rs:195-202`, OPEN-M5-10).
  - Frames: length ≠ 4352 rejected before the AEAD (`frame.rs:171`); nonce `0^16 ‖ u64be` (`secmp-crypto/src/nonce.rs:35-41`); AD label ‖ `sess_id` (`frame.rs:132-134`); strict +1 with `checked_add`; `LINK_MAX_FRAMES` refuses sealing on the client only (`frame.rs:146-151`), as docs/03:570 and OPEN-M5-03 A require (H-7 REFUTED).
  - D.1/D.2 decoders fixed BE, total and canonical: exact `len`, `ver` checked, `finish()` rejects trailing bytes (`codec.rs:258-263`, `wire/frame.rs:384-393,729-742`), canonical unpad (`codec.rs:288-299`); FETCH_MULTI count 1..=32; all size arithmetic compile-time asserted (`sizes.rs:202-238`); SEND 4181, LINK_PUT f1 4314, CELLR 4126, LINKR 4167, CONT 4106, FETCH_MULTI(32) 2822, all ≤ 4335.
  - D.6 signatures bind label, `sess_id`, `cmd_seq` and fields; MFETCH for FETCH_MULTI with the count unsigned; LINK_PUT over SHA-256 of the whole 12 360-B blob (`wire/signed.rs:20-140`).
- **Q commands and executor (`crates/secmp-relay/src/{exec,executor,plan,cmdseq}.rs`).**
  - Check order = OPEN-M5-04 (`exec.rs:120-145,156-163,175-196,266-278,282-323,373-379`); token ct-verified first (`crates/secmp-proto/src/link/ids.rs:73-85`).
  - `cmd_seq`: `last` from 0, `>` fresh and recorded, `≤` stale ⇒ one ERR 6 (`cmdseq.rs:38-45`); CONT exempt; LINK_PUT admitted at frame 1 and answered after frame 3; rate ⇒ ERR 7 (`executor.rs:90-145`), as ADR-048 (f)/(p).
  - Every response is exactly 1 / F / F_M / 3 sealed 4352-B frames by `Plan` variant, with only the D.2 ERR 6/7 exceptions (`plan.rs:84-91`); error and success frames are identical units.
  - FETCH `ack ≥ next_cell_id` ⇒ present 4, nothing deleted; FETCH_MULTI errors first in request order capped at F_M, cells by arrival, a duplicated `rid` selected once (`exec.rs:226-262`, `plan.rs:144-166`); acking cut entries is spec-conformant (docs/03:606, H-10; test gap R-140).
  - Undeclared extra rule: QUEUE_NEW whose derived `sid` names another queue ⇒ ERR_AUTH (`exec.rs:137-140`; R-138). An identical QUEUE_NEW during drain answers OK (`exec.rs:129-141`; R-119).
- **Stores, budget, sweeper, rate, drain (`queue.rs`, `linkdata.rs`, `cells.rs`, `budget.rs`, `clock.rs`, `rate.rs`, `relay.rs`).**
  - One-time consume under the global lock with a marker; the copy precedes the deletion (`exec.rs:361`, `:364`); owner status non-consuming (`exec.rs:339-386`); budget released once.
  - Stored cells and blobs wiped on every delete path (RL-10); hour buckets only; RAM-only restart; derived ids re-creatable.
  - The HELLO limit is one bucket per listener (`relay.rs:82,90,126-132`, `rate.rs:29-34`), not per connection as §9.7 item 7 says (R-108, owner §D 1(a)).
  - Every Ed25519 verify runs under the single `Mutex<State>` (`relay.rs:133-147`; R-109). No per-link or per-token quota (`exec.rs:112-146,281-334`; R-110 = OPEN-M5-07 A).
  - Drain is reachable through the API only: the binary never calls `start_drain`, SIGTERM exits at once (`crates/secmp-relay/src/main.rs:104-117`); OPEN-M5-09 "exit after `drain_secs`" is not met at M5 — an accepted gap for M10 (R-145).
- **Server loop (`server.rs`, `conn.rs`).** One `std::thread::spawn` per accepted connection with no cap (`server.rs:196-202`), `panic = "abort"` in release (`Cargo.toml:101`); accept errors other than `WouldBlock`/`Interrupted` end `serve` and the process (`server.rs:204-206`, `main.rs:115-117`); `Phase::Linked` never times out and `write_all` has no write timeout (`conn.rs:105-113`, `server.rs:80-83,234`). R-105, R-106, R-107.
- **Transport (`crates/secmp-transport/src/`).** Synchronous over `std::io` (ADR-050, §E); the client rejects any non-fitting response and closes, except `OK_SEND.evicted` = 0 or ≥ `cell_id` (`relay_queue.rs:309`; R-122); `RecvCap`/`SendCap` implement `PartialEq` with a constant-time body (`caps.rs:131-137,202-208`; R-123).
- **Harness (`crates/secmp-testkit/`).** H-01…H-13 under their TEST-SPEC names (L6 scripted check over all 232 TEST-SPEC row lines); H-12 lacks the "no mk reused" assertion (R-115); `Box::leak` of the old relay is test-only with deterministic seeds, and after `restart_relay` new connections use the new relay (`src/harness/world.rs:152-154,178-191,254,321`; R-162 REFUTED as a defect).
- **Formal (`formal/link.pvl`, `formal/link/*.pv`, `formal/CLAIMS.md` §LINK).**
  - The L7 mapping table is complete: every field, KDF, transcript, MAC, split, frame and signature layout has its model counterpart; no `nounif`; secrecy assumptions are proved by ProVerif.
  - LO-5…LO-7 exactly as decided: LO-5 outputs right after each `new` (`link.pvl:535,558,594`), LO-6 `kemr` r1/r2 output only when `rk = true` (lBoth), LO-7 unused. No trivialising abstraction; F = 2 in the model vs F = 4 in the code is sound through `formal/CLAIMS.md:334` (counters {0,1,2}, every frame counter-indexed), F to be named among the bounds (§F).
  - Deviations: L7 holds by `relay_sig` authentication alone (R-116); the gate accepts any "is false." for injective expected-false lines (R-117); "Covered" overclaims and the Excluded list is short (R-118); heading still "Planner draft v2" (R-136).
- **§11.3 statement (A1 gap S11-06).** The relay learns nothing beyond the §11.3 list. Evidence: the frame count depends on the command type only, error and success are identical 4352-B units (Q-57, V-16, P-09); a closed set of six events, none per request, with positive controls (RL-03; `event.rs`; the peer address is dropped at accept, `server.rs:105-106`; no `tracing`/`tokio` in `Cargo.lock`); stores keep hour buckets plus the global `arrival` counter only; the `Executor` holds no queue-linking state across connections; RAM only. Residuals recorded, not leaks of identities or content: aggregate link-open timing (R-108), outcome-dependent processing time of about one Ed25519 verify (R-142), availability (R-109, R-110).
- **CLAUDE.md §1 invariants.**
  - §1.1 relay learns only fixed-size cells: the §11.3 statement above.
  - §1.2 single suite: `ver` checked in every D.1/D.2 decoder (L1); §1.3 every key agreement hybrid, X25519 all-zero rejected in constant time (`secmp-crypto/src/hybrid_kem.rs:100-101,182-183` → `x25519.rs:64-67`; low-order imports refused, `x25519.rs:135`; C-19, RH-06).
  - §1.4 constant rate: not exercised by M5 — the client scheduler (spec §10) is an M6 deliverable (docs/07 §M6) and `RelayQueueTransport` is a synchronous request/response primitive without an emission policy (ADR-050), so no M5 code decides *when* a frame is sent; relay side, the frame count depends on the command type only (L2).
  - §1.5 fail closed: every LINK-level failure tears down with nothing emitted; a poisoned lock aborts; the crash of R-105/R-106 is closing, not leaking.
  - §1.6 secrets typed and zeroized: `unsafe` only in `secmp-sys-*` and the ADR-038 bench sites, `forbid(unsafe_code)` at every new root; no secret `==` or short-circuit over secret `Choice`s in `link/`, `tr/` or the relay; R-59 trial opens branch-free incl. the AEAD (`open_ct_constant_flow`), counting accessor asserted (G-01/G-02). Exceptions: R-111, R-112, R-113, R-123.
  - §1.7 persist-before-send/ack: client-side (RT §2), not touched by the relay findings.
  - §1.8 decoders total and canonical, fuzzed (29 targets).
  - §1.9 supply chain unchanged: 119 registry packages, 25 exemptions, youngest crate 19 d, no git dependencies, no build scripts, actions SHA-pinned; relay closure = crypto closure (ADR-049).
  - §1.10 frozen-file changes covered by ADR-048 (rev 2.6).
- **App. C "≥ 200 malformed encodings".** F3 count of the frozen `vectors/encodings.json` (rev 2.3, M2): 547 reject cases; D.1/D.2 rejects 233 (Request 91, Response 67, Record/HS1 17, Record/HELLO 16, RelayInfoV1 16, Record/HS2 14, Record/RELAYINFO 12). Met in the collective reading frozen at M2; a per-structure reading would be a vector re-freeze (spec revision), not M5.
- **Key handling.** The relay key file stores seeds (`relay_kem` seed 64, `relay_dh` secret 32, `relay_sig` seed 32), mode 0600. Carry-over `keys.rs:120` boundary tested (`keys::tests::rotation_boundary_new_generation_may_expire_with_the_newest`, `keys.rs:495-505`; mutant `<` → `<=` caught, 7/7).

## C. Findings

Legend. `R-nn` = row of the consolidated register (M05-R-nn); R-163/R-164 = red-team RT-02/RT-03 (RT-01 merged into R-120, the same finding). Severities are the register's FINAL severity (the verifier's where one ran); the status (CONFIRMED / PLAUSIBLE / REFUTED) leads the Finding cell. Tags in **Required action**: **C-n** = condition before merge (§G); **owner §D n** = owner approval (§D); **§F** = reviewer amendment; **F-n (Mxx)** = follow-up (§H); "register follow-up" = target taken from the register where §H gives no F-number. Locations are `@3b29ca8`; crate prefixes: relay = `crates/secmp-relay/src/`, proto = `crates/secmp-proto/src/`, transport = `crates/secmp-transport/src/`.

| # | Sev | File | Finding | Required action |
|---|---|---|---|---|
| R-105 | major | relay `server.rs:196-202`; `Cargo.toml:101` (`panic = "abort"`); `docs/05-relay-ops.md:112` (`TasksMax=512`) | **CONFIRMED** (repro V1 `err01.txt` + reading). The accept loop spawns one thread per connection with `std::thread::spawn` and no cap; ~512 idle unauthenticated connections (no HELLO token needed; RT: any pace within 30 s) make spawn panic on the serve thread → abort → restart with all queues, cells and link data lost, repeatable at will. | **C-1**: connection cap (`max_connections`, remediation default 384 < `TasksMax`) checked before spawning, over-cap streams closed; `std::thread::Builder::spawn`, `Err` → close; `LimitNOFILE` in docs/05 §4; test `server_loop::connections_over_the_cap_are_closed_without_a_thread`. |
| R-106 | major | relay `server.rs:204-206`; `main.rs:115-117`; `crates/secmp-relay/tests/relay/server_loop.rs:225-234` | **CONFIRMED** (repro V1 `err02.txt`; a test pins it). Any `accept` error other than `WouldBlock`/`Interrupted` ends `serve` and the process (EMFILE reachable with ~1 020 idle connections; `ConnectionAborted` pinned as fatal by `serve_fails_on_a_listener_error`). | **C-2**: retry on `ConnectionAborted`/`ConnectionReset`/EMFILE/ENFILE/ENOBUFS/ENOMEM; exit only for a dead listener (EBADF/EINVAL/ENOTSOCK); invert the test; tests `serve_retries_accept_errors_that_are_not_listener_failures`, `serve_fails_on_a_dead_listener`. |
| R-107 | minor | relay `conn.rs:105-113`; `server.rs:79-83`, `:234` | **CONFIRMED** (reading). A linked connection has no relay-side inactivity bound and `write_all` has no write timeout, so idle or non-reading links hold their thread forever; once the R-105 cap exists they fill it (lockout at 4 links/s). | **C-3**: write timeout 30 s in `set_poll`; `Phase::Linked` age limit 24 h (= `LINK_LIFETIME`); idle bound config `link_idle_secs`, default 900 s (M6 adjusts); tests `linked_connection_closes_after_idle_bound`, `a_blocked_writer_is_dropped`. |
| R-108 | minor | relay `relay.rs:82,90,126-132`; `conn.rs:160-163`; `rate.rs:29-34`; `docs/03:636`, `:560`; `docs/05:25,:50`; `docs/01:158` | **CONFIRMED** (lockout; mechanism) / **PLAUSIBLE** (practical observation timing). The HELLO limit is one bucket per listener, not per connection as §9.7(7) says; any onion-address holder at ≥ 4 HELLO/s locks out all new links and sees aggregate link-open timing; docs/01/05 still claim per-connection limits and Tor PoW. | **owner §D 1(a)**: ADR-048 erratum "per listener (v1); per-circuit bucket M10"; **owner §D 2**: docs/01 RR row (HELLO lockout), STRIDE D "Tor PoW" corrected; **§F** docs/05:25/:50, `HiddenServiceMaxStreams`; RL-14 text; **F-1 (M10)**. |
| R-109 | minor | relay `relay.rs:133-147`; `exec.rs:70-73,175-196,226-239` | **CONFIRMED** (mechanism); hold time estimated 1.6–3.8 ms per FETCH_MULTI, not measured. Every Ed25519 verify runs under the global `Mutex<State>`; FETCH_MULTI ×32 on own queues (or garbage-signature SEND to a known `sid`) over ~260–625 links saturates the lock for all honest commands. | No merge criterion (§E; ≈ 150-line design change). **owner §D 2**: docs/01 RR row (lock amplification); **§F** docs/05:176 "CPU negligible" struck; **F-2 (M10)**: measure, then two-phase verify, FETCH_MULTI first. |
| R-110 | minor | relay `exec.rs:112-146,281-334`; `budget.rs`; docs/03 §9.6 | **CONFIRMED** (reading + arithmetic). No per-link or per-token quota: any access-key holder fills the queue pool (11 432 reservations, ≈ 68 s at the HELLO rate) or the link-data pool (80 076, ≈ 339 s); honest QUEUE_NEW/LINK_PUT (incl. post-restart re-creation) get ERR_FULL for up to ~30 days. Code = OPEN-M5-07 A. | **owner §D 2**: docs/01 RR row (pool exhaustion by access-key holders; recovery = restart + key rotation); **§F** docs/05:134 two pools; **F-3 (M10)** pool-fill counter/runbook; **F-12 (M13)** quotas/VOPRF. |
| R-111 | minor | relay `executor.rs:329`, `:282`; proto `wire/cell.rs:31-33`; `link/cont.rs:209-227,380-399`; `wire/frame.rs:133-138` | **CONFIRMED** (reading). Response and request paths copy cells/blobs into plain `Box`es freed unwiped: acked/evicted cells and consumed one-time blobs (12 360 B, also at upload, V4) survive in freed heap, against §9.7(5) "zeroize cell buffers on delete" (review focus). Ciphertext only. | **C-4**: wiping `Drop` (or `Zeroizing<Box<…>>`) for `Cell`, `Cont.data`, `LinkPut.blob_part`, the `split_blob` part; type tests `cell_wipes_on_drop`, `cont_wipes_on_drop` (`ZeroizeOnDrop` assert); `rl_zeroize::fetch_response_copies_are_wiped`. |
| R-112 | minor | relay `keys.rs:143-160` | **CONFIRMED** (V4 field-exact replay: every growth after `sig` moved the block under glibc). `KeyFile::encode` grows a `Zeroizing<Vec>` field by field (8→16→…→1312); each `realloc` move frees an unwiped block holding the `relay_sig` seed, the access key and earlier generation seeds. CLI-only (keygen/rotate-static). | **C-5**: `Vec::with_capacity(74 + GENERATION_LEN · count)` with checked arithmetic; test `keys::tests::encode_capacity_is_exact` (`capacity() == len()` for n = 1, 2, 3, 8). |
| R-113 | minor | proto `prekeys.rs:323-338` | **CONFIRMED** (reading). `InvitationRecord::duplicate` is a public, un-gated deep copy of three secrets (`link_key`, `owner_seed`, `invq_recv_seed`) in the shipped crate; only test/kat/bench/fuzz callers; the doc still says "the link key is duplicated". | **C-6**: `#[cfg(any(test, feature = "kat"))]`; `[[test]] hx_persist required-features = ["kat"]`; fix the doc at `:323-324`; proof `cargo build -p secmp-proto --no-default-features`. |
| R-114 | minor | `docs/mutants-accepted.md:9-13`; `xtask/src/gates.rs:999-1017` | **CONFIRMED**. The mutants matcher ignores line numbers and no row carries a matched `:line`, so TEST-SPEC-M5 (i)/R-74 is not met; the two relay rows (`server.rs:81`/`:86` shims) are not equivalent mutants and have no reviewer acceptance. CI's 6 survivors map onto 5 rows. Note RT-02 (R-163): `set_poll` carries the 30-s HELLO timeout. | **C-7**: matcher keys on `path:line` + description, tests `survivor_with_unlisted_line_is_undocumented`, `survivor_with_listed_line_is_accepted`; rows `:59`, `:163` ×2, `:202`; relay shim rows removed, loopback test `server_loop::tcp_shim_close_and_read_timeout` kills both (§E). |
| R-115 | minor | `crates/secmp-testkit/tests/harness/scenarios.rs:457-548`; `TEST-SPEC-M5.md:319` (H-12) | **CONFIRMED** (absence). H-12 does not assert "no mk reused" across the restart (a rollback that re-seals under `lost-1`'s key still passes); the U[10 s, 5 min] delay is computed by the test itself; "drops its cell_id map" has no state. | **C-8**: assert pairwise-distinct message-key digests and `pos(a10) == pos(lost-2) + 1` (`h12_restart_recreate_without_mk_reuse`); relabel the delay as pacing; strike the map clause (M6, §E). |
| R-116 | minor | `formal/CLAIMS.md:381,:412`; `formal/link/lClean.pv:71`; `formal/link.pvl:466,477,592` | **CONFIRMED** (deterministic reading; the run with `link.pvl:466` deleted not performed, ProVerif absent). L7 follows from `relay_sig` authentication alone (R signs exactly one `akc`); the `akc` comparison is never exercised, so "L7 proves only that the client's check runs" is false. | **§F** CLAIMS erratum: relabel L7 as signature consistency; the `akc` compare (`link/client.rs:98-101`) is evidenced by C-11/RL-19 only. |
| R-117 | minor | `xtask/src/gates.rs:2822-2827`, `~2990-3011`; `xtask/src/expect.rs:1175,1179,1198` | **CONFIRMED** (reproduced: an edited lQKey log passes the gate, V7). The ProVerif gate drops `RESULT (but/even …)` remarks and accepts any "is false." for the injective expected-false lines L1c/L2/L6a, so a replay-only failure would pass. Today's logs print `(even … is false.)` (RT §2). | **C-9**: attach remarks to their line; `inj-event` expected-false requires `(even … is false.)`; fixtures `proverif_gate_rejects_but_remark_for_inj_expected_false`, `proverif_gate_accepts_even_remark_for_inj_expected_false`; proverif-link 9/9 unchanged. |
| R-118 | minor | `formal/CLAIMS.md:396-412`; proto `link/relay.rs:149-155,193-197`; `link/client.rs:98-101`; relay `exec.rs:149,226,266,281,339` | **CONFIRMED in part** (minor (a), (d); nit (b), (e); (c) REFUTED). §LINK "Covered" overclaims "signed commands" (only QUEUE_NEW and FETCH modelled); the Excluded list omits the multi-generation key ring, the key-less client, the 16-B truncation and F = 4 vs 2. | **§F** CLAIMS erratum, no model change: "Covered: signed `QUEUE_NEW` and `FETCH`"; Excluded rows for the key ring, the five other signed commands, the key-less client (C-11), the bounds. |
| R-119 | minor | relay `exec.rs:129-141`; `crates/secmp-relay/tests/relay/rl_conn.rs:290-342`; `OPEN-M5-decided.md:17` | **CONFIRMED** (reading). An identical QUEUE_NEW during drain answers OK (identical rule before the drain/budget check) — a wire-visible reading the literal OPEN-M5-09 text ("QUEUE_NEW ⇒ ERR 2") does not make and RL-15 does not pin. Defensible ("no new state"). | **C-10**: RL-15 assertion `rl15_drain_identical_queue_new_answers_ok` (identical → OK, digest unchanged; bad token → ERR 1); **§E/§F** OPEN-M5-09 clarification. |
| R-120 | minor | `ref/gen_vectors.py:21-22`; `ref/tests/test_link.py:114`; `ref/secmp_ref/hx_cases.py:176`; `ref/secmp_ref/vectorfile.py:308` | **CONFIRMED** (F3 reading; RT-01 executed, merged here). `SUITES` lacks `link_cases` (`KeyError: 'link'`); `hx_cases.py:176` still draws `inv_sid` (pre-ADR-048 (m)) and `suite_bytes("hx")` fails its validator; `pytest ref/tests/test_link.py ref/tests/test_hx.py`: 24 failed, 21 passed, 24 errors. Mitigated: L1 recomputation, V-22. | **C-11** (ref): `link_cases` in `SUITES`; `hx_cases` `inv_sid` per ADR-048 (m); `ref/` tests green; `gen_vectors.py link hx` reproduces `dd77bb7c…`/`2bf05e69…`; evidence file in M05-evidence. |
| R-121 | minor | proto `kani_proofs.rs:929,932`; `xtask/src/expect.rs:733-741` (`KANI_COVERS`) | **CONFIRMED** (F3 reading). K-01's `assume(j < n)` and `assume(k > n && k < 4336)` prune every later assertion for n = 0 and n = 4335 (the max-payload boundary), undisclosed beyond SCAN_WINDOW; K-01/K-03/K-08 have no `kani::cover!`. | **C-12**: `if` instead of `assume` for n = 0/4335; `kani::cover!` in K-01, K-03, K-08; disclosure in the report. |
| R-122 | nit | proto `wire/frame.rs:683-690`; transport `relay_queue.rs:309` | **CONFIRMED** (OK_SEND half); CELLR `cell_id 0` half REFUTED at the client (V10). The client accepts `OK_SEND.evicted` = 0 or ≥ `cell_id`, which no honest relay produces (OPEN-M5-11 A); availability only, no outbox in M5. | **F-4 (M6)**: client accepts `None` or `Some(1..cell_id)`; test `ok_send_with_implausible_evicted_id_is_rejected`; decoder unchanged. |
| R-123 | nit | transport `caps.rs:131-137,202-208` | **CONFIRMED**. `RecvCap`/`SendCap` implement `PartialEq/Eq` (constant-time body) on seed-bearing types, against docs/06 §2 / CS-2.1 "no PartialEq"; callers are tests only. | **F-5 (M6)**: `impl ConstantTimeEq` instead of `PartialEq`; the 6 test sites use `ct_eq`. |
| R-124 | nit | `crates/secmp-testkit/benches/ct.rs:3505-3770`; proto `link/relay.rs:215`, `link/client.rs:185`, `link/ids.rs:79`; `crates/secmp-crypto/src/mac.rs:70` | **CONFIRMED** (facts); over-claim REFUTED. CT-01…04 cannot detect a reintroduced `==` at the four MAC/tag/token sites (composed calls ≫ floor); no static guard pins the sites; TEST-SPEC already says "composed, floor-only". | **F-6 (M6)**: static testscan rule pinning `ct_eq`/`hmac_sha256_verify` at the four sites; one TEST-SPEC (g) sentence. |
| R-125 | nit | `docs/reviews/M05-evidence/` (no CI ct JSON); REPORT Block B | **CONFIRMED** at filing; substance RESOLVED (V12 `ct-check` PASS). The CI ct record was not in the evidence; re-derived: PASS, CT-01…06 max\|t\| ≤ 2.79, `caead_derive` SUB_FLOOR_SHIFT admissible (Δ 0.099 floors); "FAIL p90 122.6" belongs to `min_leak_control`. | **C-13**: commit `ct-report-linux-37882708499.json` + `ct-progress.jsonl`; record CT-01…06 and `caead_derive` in the report; correct the Block-B attribution. **F-17 (M10)**: ct JSON carries the head sha. |
| R-126 | nit | `xtask/src/expect.rs:26-27`; `xtask/src/policy.rs:570-633` | **CONFIRMED** (facts); ADR-violation reading REFUTED. No gate pins the std-only closure of `secmp-relay`/`secmp-transport` (ADR-049/050); held by the ADR process (docs/06 §3 scopes zero-exemption to crypto/proto). | **F-7 (M6)**: policy test `relay_and_transport_normal_dependencies_are_workspace_only` (engineering-ADR line), before the tokio ADR. |
| R-127 | nit | `docs/reviews/M05-evidence/fuzz-m5b-local.log:17-30` | **CONFIRMED** (numbers). FZ-07/08 smoke depth is weak (752 runs, `lim` pinned at the seed length 532/44 B); "fuzz target for the executor" is met formally. | **F-8 (M6)**: larger nightly share and `-len_control=0` (or a near-max seed) for FZ-07/08; record runs/`lim`. |
| R-128 | nit | relay `clock.rs:34-43`; `linkdata.rs:88`; docs/03 §9.7 item 3 | **CONFIRMED** (documentation gap). The expiry boundary "expired iff now > anchor + T; link data valid through `expires_bucket`" lives only in `OPEN-M5-decided:13`, not in docs/03 or docs/08; both sides pinned by tests. | **owner §D 1(b)**: ADR-048 erratum line in §9.7(3). |
| R-129 | nit | relay `budget.rs:2,14-20`; `docs/05-relay-ops.md:134` | **CONFIRMED** (sizes, `size_of`); "transient 129th stored cell" REFUTED (V3). `QUEUE_OVERHEAD` 512 B vs ≈ 6 426 B real per full queue (≈ 1 % undercount, ≈ 68 MB at default) contradicts "worst case"; docs/05:134 shows one 6 GB pool, the code has 6 GB + 1 GB. | **F-9 (M10)**: `QUEUE_OVERHEAD` only with a `size_of` test, decided in the load test; "worst case" → "accounted bound"; **§F** docs/05:134 two pools. |
| R-130 | nit | `docs/01-threat-model.md:192` | **CONFIRMED** (process; unverified by a verifier). The R-59 status paragraph in docs/01 is not covered by ADR-048 Part 5 (BRIEF_M5 dictated it); its content checks out. | **owner §D 1(e)**: ADR-048 erratum E-9. |
| R-131 | nit | `crates/secmp-testkit/Cargo.toml:21` | **CONFIRMED** (unverified). The manifest comment names feature `kat` (it is `harness`) and omits the normal `serde_json` dependency. | **F-10 (M6)**: fix the comment. |
| R-132 | nit | `crates/secmp-testkit/Cargo.toml:26-27` | **CONFIRMED** (unverified). relay/transport are path dependencies, not `[workspace.dependencies]`. | **F-10 (M6)**: move to workspace dependencies. |
| R-133 | nit | `.github/workflows/ci-dispatch.yml:20`; `.github/workflows/fuzz-nightly.yml:10` | **CONFIRMED** (unverified). The dispatch input omits `proverif-link`; the nightly comment says 14 targets / 1 028 s (actual 29 × 496 s; the report's 533 s is stale). | **F-10 (M6)**: fix both texts. |
| R-134 | nit | `crates/secmp-relay/tests/relay/vectors.rs:592-596` | **CONFIRMED** (unverified). V-16 re-pads already-opened payloads and asserts 4336 B — tautological (compensated by the byte-exact frame checks). | **F-11 (M6)**: delete, or replace by an `unpad` check. |
| R-135 | nit | `crates/secmp-testkit/tests/harness/scenarios.rs:369` | **CONFIRMED** (unverified). The comment claims an identical QUEUE_NEW is answered; no assertion. | **F-11 (M6)**: add the call or drop the comment. |
| R-136 | nit | `formal/CLAIMS.md:320` | **CONFIRMED** (unverified). The frozen §LINK is still headed "Planner draft v2 for the reviewer"; the planning→final diff weakens nothing. | **§F**: heading "frozen 2026-10-07, errata 2026-10-09". |
| R-137 | nit | `vectors/SCHEMA-4.11-link.md` (rev-2.3 line refs); `docs/01-threat-model.md:187-188` | **CONFIRMED** (RR-16 gap) / **PLAUSIBLE** (SCHEMA-4.11 anchors, not re-checked). SCHEMA-4.11 cites rev-2.3 docs/03 line numbers; the docs/01 residual register jumps RR-15 → RR-17. | **owner §D 2**: RR-16 gap noted editorially; SCHEMA re-anchor: register erratum (no judge disposition). |
| R-138 | note | relay `exec.rs:137-140` | **CONFIRMED** (reading). Undeclared extra rule: a QUEUE_NEW whose derived `sid` names another queue → ERR_AUTH; reachable only by a 128-bit collision; fail-closed; not in §9.3/§9.7(8) nor report §5; the ref silently overwrites. | **C-13**: report §5 line (sid collision); **owner §D 1(c)**: ADR-048 erratum (§9.3 QUEUE_NEW with a foreign-held `sid` → ERR_AUTH). No code change. |
| R-139 | note | relay `executor.rs:90-96,139-144,219-224` | **CONFIRMED** (consistent reading, H-4). Over-rate SKEY → ERR 7 (the D.2 exceptions override the SKEY table row); the stale-over-rate precedence is declared only in the report; no test for over-rate SKEY. | **C-10**: RL-13 assertion `rl13_over_rate_skey_is_err_7_and_records_cmd_seq`; **owner §D 1(d)**: §8.5/D.2 precedence stale (ERR 6) before rate (ERR 7), also for SKEY. |
| R-140 | note | relay `exec.rs:175-196,226-262`; `plan.rs:144-165` | **CONFIRMED**; spec-conformant (H-10). FETCH_MULTI acks entries whose results are cut by the F_M error cap; a duplicated `rid` can yield both an error frame and cells; "acked but unreported" untested (SQ-28 "No case"). | **C-13**: Q-25 extended with a valid 10th entry, `q25_acked_but_unreported_entry_still_deletes`. |
| R-141 | note | relay `executor.rs:246-253,276-280`; `exec.rs:339-372` | **REFUTED** (stated mechanism; PLAUSIBLE at filing). A one-time consume draws no entropy in `render`; the copy precedes the deletion; a lost response loses the blob exactly as a Tor drop would. | None; optional report sentence (§9.4: atomic against other consumers, not with delivery). |
| R-142 | note | relay `exec.rs:120-146,156-163,183-188,267-273,373-379`; `executor.rs:20` | **CONFIRMED** (code, L3) / **PLAUSIBLE** (Tor measurability, L2). Relay processing time depends on the outcome (≈ one Ed25519 verify), a timing echo for id holders of what the ERR codes already reveal; the global lock carries a weak cross-link load signal. Not in §11.3, no spec duty. | None; recorded in the §11.3 statement (§B). |
| R-143 | note | proto `prekeys.rs:650` | **CONFIRMED** (reading; unverified). The invitation queue key is a fresh draw, not from the §10.6 pool as §5.2 (ADR-048 (m)) states; consistent with OPEN-M5-14 B; the derivation is correct. | **F-14 (M7)**: client core takes it from the pool; test that queue keys are independent of the IKS (§9.2). |
| R-144 | note | proto `link/relay.rs:105` | **CONFIRMED** (reading; unverified). `relay_info` signs the empty message with the long-term `relay_sig` as a placeholder on every HELLO, then discards it. | Register follow-up (M6): build the 1677-B prefix without a placeholder signature. |
| R-145 | note | relay `server.rs:178-209`; `main.rs:104-117` | **CONFIRMED** (reading). The binary never calls `start_drain` (no signal handling); SIGTERM/abort skip all wipes; detached threads outlive `main`. OPEN-M5-09 drain is API-level only — declared. | Register follow-up (M10): drain trigger, drop/clear `Relay` before exit. Drain stated as an accepted gap, not met (§B). |
| R-146 | note | proto `link/ids.rs:18`; relay `keys.rs:253-256`; transport `caps.rs`; proto `prekeys.rs:294-297` | **CONFIRMED** (facts; unverified); not a violation. The access key, queue seeds and invitation seeds are long-lived `SecretBytes`, not `LockedSecret` (R-37 precedent; relay `mlockall` is M10). | Register follow-up (M7/M10): reviewer ruling (`LockedSecret` or covered by `mlockall`). |
| R-147 | note | relay `keys.rs:118-131,232-239` | **CONFIRMED** (reading; unverified). `rotate` prunes before its last refusals; a failed `replace` leaves `<path>.new` (full key material) that blocks later rotations; no directory fsync. Seeds stored, 0600. | Register follow-up (M10): prune after all checks; clean `.new` on failure; fsync the directory. |
| R-148 | note | REPORT Block E; `xtask/src/gates.rs:1405-1412` | **CONFIRMED**. crypto unviable 38.4 % (> 35 %, WARNING only, ADR-047 Am. 2), up from 36.9 % (M4); caught 61.3 % ≥ 50 %; no breakdown of this run in the report. | **F-15 (M6)**: unviable breakdown for crypto (§E: informative). |
| R-149 | note | `formal/link.pvl:108-115`; CLAIMS "Reviewer decisions" LO-5/LO-6 | **CONFIRMED** (reading; unverified). "The two attackers are equally powerful" is inexact: the phase-0 reveal is a superset of the oracle; no soundness effect. | §E confirms LO-5…LO-7 sound; register erratum "at least as powerful (⊇)". |
| R-150 | note | `formal/link/lBoth.pv:32-33` | **CONFIRMED** (unverified). L3c (r2c) is false via an integrity trace (the attacker's own QUEUE_NEW), not leakage of an honest response. | Register follow-up (M11): restrict r2c secrecy to R's fresh CELLR content with L10. |
| R-151 | note | `xtask/src/gates.rs:5098-5175` (X-04) | **CONFIRMED** (unverified). X-04 does not check that a CLAIMS ID's query has the right shape/file; the binding rests on pinned model hashes and review. | Register follow-up (M11, optional): file + query-shape check per ID class. |
| R-152 | note | REPORT Block E | **CONFIRMED**. lBoth 1139 s of the 1800 s cap (63 %); LO-7 forbids splitting, so headroom is small. | None; watch on any `link.pvl` change. |
| R-153 | note | `docs/08-decisions.md:566` (ADR-050 Proposed) | **CONFIRMED**. Transport/testkit shape (sync `std::io`, seeds as parameters) and the §12.1 `#[async_trait]` deviation rest on an unaccepted engineering ADR; supply-chain side clean. | **§E**: ADR-050 Accepted; **owner §D 3**. |
| R-154 | note | `docs/08-decisions.md:301` (ADR-042 M5-C line); `xtask/src/gates.rs:924` | **CONFIRMED**. Coverage feature `secmp-testkit/harness` is used by the gate while its consequence line awaits acceptance; CI coverage PASS (testkit 94.3 %, transport 89.7 %); transport has no own unit tests. | **§E**: consequence line accepted 2026-10-09. |
| R-155 | note | xtask policy (no `#[ignore]` scan) | **CONFIRMED** (A3; tree clean today). CLAUDE.md §6 "no `#[ignore]` without ADR" is not gate-enforced. | Register follow-up (M6): testscan rule. |
| R-156 | note | `xtask/src/gates.rs:4544,4583,4617-4621` | **CONFIRMED** still open. The M04 F-M5 note "nextest LEAK of the Windows fake bench" (`ping` child outlives the killed `cmd.exe`) is not mentioned in the report. | **F-16 (M9)** with R-164. |
| R-157 | note | `crates/secmp-relay/tests/relay/props.rs:71-80,1152,1542` | **CONFIRMED**. P-06…P-11 are seeded loops with small default case counts, no CI override; power from the step count and Q-42. | None (record). |
| R-158 | note | `.github/workflows/ci.yml:303-307` | **CONFIRMED** (pattern; unverified). "Re-run failed jobs" on mutants shards makes the merge see < 8 shards (fail-closed). | None (record). |
| R-159 | note | `docs/reviews/M05-evidence/ct-summary-local-scale10.txt` | **CONFIRMED**. The local scale-10 ct run (M1 Pro, pre-pin) is informative only; correctly labelled. | None (record). |
| R-160 | note | proto `link/mod.rs:107-136` | **CONFIRMED**. `HandshakeTrace` (kat only) holds plain `Clone` secrets; never in a shipped build. | None (record). |
| R-161 | note | `docs/01:48,161`; `docs/02:111` | **REFUTED** (as a silent spec change). The E-4 wording is an admissible editorial application of ADR-048 Part 5 (`docs/08:522` prescribes the plural). | None. |
| R-162 | note | `crates/secmp-testkit/src/harness/world.rs:152-154,178-191` | **REFUTED** (as a defect). Harness `Box::leak` (Dev. 5C-8) is test-only with deterministic seeds; pins 3 locked pages per relay. | None (§E: test-only). |
| R-163 (RT-02) | note | relay `server.rs:80-83,213-217` | **CONFIRMED** (reading). The 30-s pre-HELLO bound (`conn.rs:104-113`) works in the binary only through `set_poll`'s read timeout, a documented, non-equivalent mutation survivor (shard 4); with the mutant a pre-HELLO connection holds its thread indefinitely and R-105 needs no reconnect pacing. | Covered by **C-1/C-3** and the **C-7** loopback test (§E: rows not accepted). |
| R-164 (RT-03) | nit | `xtask/src/gates.rs:4617-4624`; `docs/reviews/M04-review.md:203,205`; `docs/reviews/M05-report.md:512-531` | **CONFIRMED** (reading). The M04 Windows fake-bench LEAK is unchanged at the pin (no tree kill); the report does not mention it yet states "No F-M5 line is deferred"; docs/07 M5 has no "Windows work" to attach it to. | **F-16 (M9)**; one line in report §10.2. |

**Refuted or downgraded.**

- R-141 (L1-04): the stated mechanism is refuted (V10): only `blob: None` draws entropy (`executor.rs:276-280`); the copy (`exec.rs:361`) precedes the deletion (`:364`); upheld as a note by RT.
- R-161 (L2-04): E-4 wording admissible, `docs/08:522` prescribes the plural; RT upheld.
- R-162 (L4-07): `Box::leak` test-only; `secmp-testkit` appears only under `[dev-dependencies]` (`crates/secmp-crypto/Cargo.toml:35-36`); RT upheld.
- H-2 (V9-02): an expired relay key generation is unusable — `usable(kid, now)` is checked before `on_hs1` (`conn.rs:195-202`, `keys.rs:329-334`); erased at the next `rotate-static`, not at `valid_until`; the client checks the signed `valid_until` (`client.rs:87-97`).
- H-7 (V11): the `LINK_MAX_FRAMES` bound is client-only (docs/03:570, OPEN-M5-03 A); receive overflow impossible (`checked_add`, `frame.rs:48-50`).
- H-9 (V11): every post-mutation failure tears down (`executor.rs:205-207`); `commit` cannot fail there.
- H-10 (V10-1): FETCH_MULTI acking cut entries is spec-conformant (docs/03:606); test gap only (R-140, C-13).
- H-12 (V11): stored items carry hour buckets only; the ms values (`rate.rs` `last_ms`, `conn.rs` `since_ms`) are per-link RAM; `arrival` is spec-mandated (docs/03:591).
- Parts: R-118 (c) relay error responses — already listed as L10, deferred to M11 (V7); R-122 CELLR `cell_id 0` half (V10-2); R-129 "transient 129th stored cell" (V3).
- Downgraded by verifiers, upheld by RT: R-124 (L3-01, V8), R-125 (L3-02, V12), R-126 (L5-01, V8) minor → nit. RT overturned none and upgraded none (RT §1, §3).

**Dissents (lens vs verifier; RT upheld every verifier verdict).**

- R-108: L2 (observation channel primary, minor) vs L8 (lockout, "minor, owner question") vs V2 (lockout minor; observation increment note-level, since a contact already sees online periods from dummies). RT: minor; the literal "per-connection" is met by construction, the listener bucket is an owner trade-off.
- R-109: L8 PLAUSIBLE vs V3 CONFIRMED (mechanism).
- R-112: L4 PLAUSIBLE (allocator-dependent) vs V4 CONFIRMED (replay moved the block; the lens's growth sequence corrected).
- R-118: L7 (c) gap vs V7 REFUTED (listed as L10, M11); V7 corrects L7's line references.
- R-123: L4 minor vs V5 nit (precedent M02 F1, M03 R-24).
- R-124: L3 minor vs V8 nit (claims modest; declared floor-only design, ADR-041 Am. 1).
- R-125: L3 minor vs V12 nit (re-derived, PASS stands).
- R-126: L5 minor vs V8 nit (docs/06 §3 scope).
- R-127: L6 minor vs V6 nit.
- R-129: L8 PLAUSIBLE vs V3 CONFIRMED.
- R-141: L1 PLAUSIBLE (consume lost on a local abort) vs V10 REFUTED (no entropy drawn on that path).
- R-142: L2 PLAUSIBLE vs L3 CONFIRMED (same facts, different evidence bar).
- R-105/R-106 blocker question (RT §2): not a blocker — no §1 invariant breaks, sessions survive by design (`docs/01:54`), availability only; major stands as a merge condition, not as an M10 follow-up.

**External reviews.** None in this round. GLM and Codex follow after the merge; adjudication as in M04-external.

**Follow-up index.**

- **M6:** F-4 (R-122), F-5 (R-123), F-6 (R-124), F-7 (R-126), F-8 (R-127), F-10 (R-131, R-132, R-133), F-11 (R-134, R-135), F-15 (R-148); register follow-ups R-144, R-155; M6 client backoff with jitter (F-1).
- **M7:** F-13 (P-12/R-56 end to end), F-14 (R-143, §9.2); register follow-up R-146 (with M10).
- **M9:** F-16 (R-156, R-164).
- **M10:** F-1 (R-108), F-2 (R-109), F-3 (R-110), F-9 (R-129), F-17 (R-125); register follow-ups R-145, R-147.
- **M11:** register follow-ups R-150, R-151 (optional).
- **M13:** F-12 (R-110).

## D. Owner approvals prepared by the reviewer

Default: 24 h, effective 2026-10-10 ≈ 10:00 UTC.

1. **ADR-048 errata set** (docs/03 text, owner class; texts remediation Group B):
   - (a) §9.7(7), §8.3, docs/05:25, :50 "per-connection" → "per listener (v1); per-circuit bucket M10" (R-108).
   - (b) §9.7(3) expiry boundary: "expired iff `now_bucket` > anchor + T; link data valid through `expires_bucket`" (R-128).
   - (c) §9.3 QUEUE_NEW with a `sid` held by another queue → ERR_AUTH (R-138).
   - (d) §8.5/D.2 precedence: stale (ERR 6) before rate (ERR 7), also for SKEY (H-4, R-139).
   - (e) E-9: the docs/01:192 R-59 status paragraph (R-130).
2. **docs/01 lines** (owner class): RR rows for the HELLO lockout (R-108), lock amplification (R-109) and pool exhaustion by access-key holders (R-110); STRIDE D column "Tor PoW" corrected (PoW is off, `docs/05:39`); the RR-16 gap noted editorially (R-137). **Recommend: accept.**
3. **ADR-050** (synchronous transport, no async runtime in M5): accepted by the reviewer as an engineering ADR (§E). Owner reservation only if the owner reads the §12.1 `#[async_trait]` signature as protocol text. Default: accepted; M6 brings the asynchronous driver with its own ADR.

## E. Reviewer decisions

| Item | Decision |
|---|---|
| ADR-050 | **Accepted** (reviewer, owner delegation of 2026-09-30), dated 2026-10-09 (R-153). |
| ADR-042 consequence line "COVERAGE_FEATURES + secmp-testkit/harness" | Accepted 2026-10-09 (R-154); the Phase-B line `secmp-relay/kat` was accepted on 2026-10-08. |
| LO-5 / LO-6 / LO-7 | Confirmed sound (L7-03, V7, RT): reveal ⊇ oracle; expected-true lines proved against the stronger attacker; expected-false lines via honest pairs; no phases in lDH/lBoth. |
| Carry-over `keys.rs:120` | Done (test `keys.rs:495`, 7/7 mutants caught); no `mutants-accepted` entry — confirmed. |
| Report deviations §5A | Accepted: R-104; the E-4 wording is admissible (`docs/08:522` plural); K-01 SCAN_WINDOW with the condition R-121 (C-12); FUZZ_TRACKED_ONLY lifted, confirmed. |
| Report deviations §5B | Accepted: ADR-049, the PV-01 readings. |
| Report deviations §5C 1–10 | Accepted. 2 (A1 draw accounting) and 4 (draw order) recorded as readings; 7 (H-12 map vacuous) → strike the sentence (M6); 8 (`Box::leak`) → test-only, refuted as a defect (L4-07, RT; R-162). |
| `docs/mutants-accepted.md` rows | `inv.rs:163` (×2), `inv.rs:202`, `secret.rs:59` accepted (equivalent, or the docs/06:83 case; M01 precedent). `server.rs:81` and `:86` **not accepted** (not equivalent; `set_poll` carries the 30-s HELLO timeout, RT-02): loopback integration test (docs/06:95 permits network outside unit tests), rows removed (C-7). |
| OPEN-M5-09 clarification | "QUEUE_NEW ⇒ ERR 2" applies to requests that would create state; an identical QUEUE_NEW (idempotent, no new state) answers OK also during drain; LINK_PUT ⇒ ERR 2 unchanged (R-119). |
| R-56 / P-12 | Function level only: accepted; the end-to-end run is F-13 (M7, with the store). |
| crypto unviable 38.4 % | WARNING, informative (ADR-047 Am. 2); breakdown F-15 (EV-8, R-148). |
| L8-05 "verify outside the lock" | Not a merge criterion (design change ≈ 150 lines) → F-2 (M10) with measurement in the load test; residual risk in docs/01/05 (§D 2, §F). |
| Report checklist "ci green" | Unchecked in the report; done by run `37882708499`; tick it in the fix report. |

## F. Reviewer amendments to the documents (2026-10-09)

The reviewer writes these into `docs/` himself (reviewer docs commit of the fix round). Texts: remediation Group B.

| # | File | Amendment | RID |
|---|---|---|---|
| A-1 | `formal/CLAIMS.md` §LINK | Relabel L7 (signature consistency; the `akc` comparison evidenced only by C-11/RL-19) | R-116 |
| A-2 | `formal/CLAIMS.md` §LINK | Narrow "Covered" to QUEUE_NEW + FETCH; Excluded rows for the key ring, the five other signed commands, the key-less client, the 16-B truncation, F = 4 vs 2 | R-118 |
| A-3 | `formal/CLAIMS.md:320` | Heading "Planner draft v2" → "frozen 2026-10-07, errata 2026-10-09" | R-136 |
| A-4 | `formal/CLAIMS.md` (bounds) | Name F among the bounds (`CLAIMS.md:334`) | H-15 |
| A-5 | `docs/08-decisions.md` | ADR-050 status Accepted; ADR-042 consequence line accepted; ADR-048 errata drafts (a)–(e) as "proposed, owner default 2026-10-10" | R-153, R-154, §D 1 |
| A-6 | `docs/reviews/M05-planning/OPEN-M5-decided.md` | Append the OPEN-M5-09 clarification (§E) | R-119 |
| A-7 | `docs/05-relay-ops.md` §4 | `LimitNOFILE`/`TasksMax` note for C-1; state the connection cap | R-105, R-106 |
| A-8 | `docs/05-relay-ops.md:36-43` (torrc) | `HiddenServiceMaxStreams` line (recommendation) | R-105, R-108 |
| A-9 | `docs/05-relay-ops.md:134` | Two pools (queue pool and link-data pool) | R-110, R-129 |
| A-10 | `docs/05-relay-ops.md:176` | Strike "CPU negligible" (one Ed25519 verify per signed command, up to 32 per FETCH_MULTI, under the state lock) | R-109 |
| A-11 | `docs/07-milestones.md` §M5 | Status paragraph "review 2026-10-09: APPROVED WITH CONDITIONS, C-1…C-13; fix round follows" | — |

docs/05 is an engineering document (reviewer class). The docs/01 and docs/03 texts are owner class (§D).

**Report corrections owed by the fix round** (`docs/reviews/M05-report.md@3b29ca8`):

| # | Correction | RID |
|---|---|---|
| E-1 | Record CT-01…06 max\|t\| and `caead_derive` p95 (t 45.45/45.88, Δ 0.099/0.089 floors); "FAIL p90 122.6/122.5" is `min_leak_control` | R-125 (C-13) |
| E-2 | §5 line: QUEUE_NEW with a derived `sid` naming another queue → ERR_AUTH | R-138 (C-13) |
| E-3 | K-01 `assume` pruning disclosed | R-121 (C-12) |
| E-4 | §10.2: the Windows fake-bench LEAK re-targeted to M9 | R-164 (F-16) |
| E-5 | §7B line 325 "thread-per-connection (M10 load test)" → cap, accept policy and idle bound | R-105…R-107 (remediation B) |
| E-6 | §9 checklist "ci green" ticked (run `37882708499`) | §E |

## G. Conditions before merge (owner of each as listed)

No new dependency, no threshold change, no vector change in any condition. The reviewer delivers the §F amendments and the §D memo.

| # | Condition | Owner | Covers (§C rows) |
|---|---|---|---|
| **C-1** | Connection cap checked before spawning + `std::thread::Builder::spawn` (`Err` → close the stream); `LimitNOFILE` in docs/05 §4; test `server_loop::connections_over_the_cap_are_closed_without_a_thread`; V1 repro repeated (PID alive) | main (Opus) | R-105, R-163 |
| **C-2** | Accept-error resilience (retry per-connection and resource errors, exit only for a dead listener); invert `serve_fails_on_a_listener_error`; tests `serve_retries_accept_errors_that_are_not_listener_failures`, `serve_fails_on_a_dead_listener` | main | R-106 |
| **C-3** | Write timeout 30 s; `Phase::Linked` age limit 24 h (= `LINK_LIFETIME`); idle bound config `link_idle_secs`, default 900 s (M6 adjusts); tests `linked_connection_closes_after_idle_bound`, `set_poll_sets_a_write_timeout`, `a_blocked_writer_is_dropped` | main | R-107, R-163 |
| **C-4** | Wiping `Drop` for `Cell`, `Cont.data`, `LinkPut.blob_part` + type test (`cell_wipes_on_drop`, `cont_wipes_on_drop`) | main | R-111 |
| **C-5** | `with_capacity` in `KeyFile::encode` + `capacity() == len()` test (`encode_capacity_is_exact`) | main | R-112 |
| **C-6** | `duplicate` under `cfg(any(test, feature = "kat"))`; `hx_persist` `required-features = ["kat"]`; doc fixed | main | R-113 |
| **C-7** | Mutants matcher on `path:line`; `:line` rows; relay shim rows removed; loopback test for `set_poll`/`close` (`server_loop::tcp_shim_close_and_read_timeout`) | main | R-114, R-163 |
| **C-8** | H-12 assertion: pairwise-distinct message-key digests and positions (`h12_restart_recreate_without_mk_reuse`) | main | R-115 |
| **C-9** | ProVerif gate: `inj-event` expected-false requires "(even … is false.)" + negative fixture | main | R-117 |
| **C-10** | RL-15 assertion: identical QUEUE_NEW during drain → OK; H-4 RL-13 assertion: over-rate SKEY → ERR 7 | main | R-119, R-139 |
| **C-11** | `ref/`: `link_cases` in `SUITES`; `hx_cases` `inv_sid` per ADR-048 (m); `ref/` tests green; evidence file | ref | R-120 (RT-01) |
| **C-12** | K-01 `if` instead of `assume` for n = 0/4335; `kani::cover!` in K-01, K-03, K-08; disclosure in the report | main | R-121 |
| **C-13** | Evidence: CI ct JSON + progress into `M05-evidence/`; report Block-B attribution corrected; §5 line sid collision; Q-25 extended by the acked-not-reported entry | main | R-125, R-138, R-140 |

Owner assignment per the judge: main runs on Opus for C-1…C-3 and C-12; the rest is Sonnet-capable, one conversation. C-11 runs in parallel on the ref instance.

**GO condition.** (i) C-1…C-13 landed; (ii) a green PR run on the fix head with the Linux ct report and a non-vacuous mutants verdict (6 → 0 unaccepted survivors, matcher `path:line`); (iii) `ref/` tests green with the evidence file; (iv) the reviewer's delta verification `3b29ca8..<fix head>`.

## H. Verdict

**APPROVED WITH CONDITIONS.** No blocker; two CONFIRMED majors (R-105, R-106 — unauthenticated relay crash with total loss of the RAM state, reproduced by V1); no CLAUDE.md §1 invariant violated (nothing leaks, dying is fail-closed, §1.7 is client-side, re-creation after a restart is the design path H-12; RT §2). The one set of corrections to APPROVED: C-1…C-13 (code: connection limit + accept resilience + timeouts, wipe drops, key-file capacity, `duplicate` gate, mutants matcher, H-12 assertion, ProVerif gate rule, RL-15/RL-13 assertions, Kani guards/covers; `ref/`: link suite and hx generator; evidence: ct JSON + report corrections) and the reviewer amendments of §F.

**GO condition.** As §G: a green PR run on the fix head, the Linux ct report, a non-vacuous mutants verdict (6 → 0 unaccepted survivors, matcher `path:line`), `ref/` tests green, and the reviewer's delta verification `3b29ca8..<fix head>`.

Next (2026-10-09): fix brief BRIEF_M5-FIX (main; Opus for C-1…C-3 and C-12, the rest Sonnet-capable — one conversation) and WEISUNG_REF_M5-3 (C-11) in parallel; reviewer docs commit (§F); PR run; delta verification; GO_M5.

**Follow-ups carried forward** (target milestones from the register and remediation Group C):

- F-1 — per-circuit HELLO bucket via `HiddenServiceExportCircuitID` (M10; client backoff with jitter M6) — R-108.
- F-2 — lock measurement in the load test, then two-phase verify, FETCH_MULTI first (M10) — R-109.
- F-3 — aggregate pool-fill counter and runbook entry (M10) — R-110.
- F-4 — `evicted` range check in the client (M6) — R-122.
- F-5 — `ConstantTimeEq` instead of `PartialEq` on `RecvCap`/`SendCap` (M6) — R-123.
- F-6 — static `ct_eq` guard rule at the MAC/tag/token sites (M6) — R-124.
- F-7 — policy test: std-only normal dependencies of relay/transport (M6) — R-126.
- F-8 — fuzz nightly share and `-len_control=0` for FZ-07/08 (M6) — R-127.
- F-9 — `QUEUE_OVERHEAD` tied to `size_of` (M10) — R-129.
- F-10 — manifest and workflow texts (M6) — R-131, R-132, R-133.
- F-11 — V-16 tautology and `scenarios.rs:369` comment (M6) — R-134, R-135.
- F-12 — per-token quotas with VOPRF tokens (M13) — R-110.
- F-13 — P-12/R-56 end to end, with the store (M7) — §E.
- F-14 — §9.2 test: queue keys never linked to the IKS (M7) — R-143.
- F-15 — unviable breakdown for `secmp-crypto` (M6) — R-148.
- F-16 — Windows fake-bench LEAK, tree kill (M9) — R-156, R-164 (RT-03).
- F-17 — ct JSON carries the head sha (M10, engineering ADR) — R-125.
