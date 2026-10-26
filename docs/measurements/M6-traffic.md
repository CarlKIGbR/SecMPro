# M6 traffic measurements (BRIEF M6-C2 §C2-4, `docs/07` §M6, ADR-018)

Status: **Phase C final for the review of M6.** Every number below is quoted from a file under
`docs/measurements/M6-evidence/` or labelled as a model value derived from the spec. A number that needs an
owner-operated measurement carries the reason and the date of its absence. ADR-018 stays "Proposed (owner decides after M6)".

## Method

- **Where.** The local figures come from the container `secmp-main` (carlgpu4; 32 logical CPUs, Linux 7.0.0-34-generic), the
  `kat` harness binary of `secmp-testkit` (`cargo nextest run -p secmp-testkit --features kat`, test profile with `opt-level = 3`
  for dependencies and the two crypto crates), on 2026-10-22. The CI figures come from PR run #176 (`a265384`, run id
  39776847202; `docs/measurements/M6-evidence/ci-run-176.txt`); the `windows-native` figures of that run are void (stack overflow,
  fixed in `1769900`); the `windows-native` figures come from PR run 39939400878 (`60083af`; `M6-evidence/ci-run-182-windows.txt`).
- **Bandwidth (MR-01, `bandwidth_model_matches_capture`).** The whole client side runs on the virtual clock against the relay
  (`Rig`): 24 virtual hours per mode, every frame is captured; the model — units × 4 352 B + 5 765 B per handshake — is checked
  against the capture connection by connection, the steady-state rate is the capture's bytes per second while the links are up.
  Scenarios: Strict, one contact, P = 10 s; Balanced, four contacts, P = 10 s; Low-bw, five contacts, P = 40 s.
- **Drain (MR-02, `drain_after_offline_virtual`).** The recipient is offline for 1 h or 24 h while the senders keep sending at their
  periods; the relay evicts what the 128-cell queues cannot hold; the recipient returns and the run counts the ticks until every
  queue is acknowledged.
- **CPU (MR-05, `cpu_per_slot_measured`).** The wall time of `Conversation::prepare_direct` (TR encrypt, persist into the in-memory
  store, seal) over 10 000 slots (exactly three rounds, the minimum p99 is judged: shared host), one slot in two with a real 200-byte message, the others dummies (the same code path); and the wall
  time of one virtual hour of the whole rig per mode divided by 3 600 s. The rig is single-threaded and includes the relay and the
  virtual transports, so the percentage is an upper bound of the client's own share of a core; it contains no I/O wait, no crypto of the
  link layer over a real socket and no UI.
- **Tor and the Windows VM.** Not available to the executor (owner-operated, `docs/reviews/M06-report.md` §6).

### CI figures (run #176)

| gate | result | duration |
|---|---|---|
| `kani` (job 119817852835) | 46/46 harnesses verified | step 6 658 s, job 1 h 51 m |
| `fuzz` (119817852743) | 33 targets, 120 s each, PASS | step 4 335 s, job 1 h 13 m |
| `ct` (119817852871) | success; no figure quoted (the step summary is not in the log) | job 1 h 49 m |
| `proverif-hx` / `proverif-link` | PASS, 31 of 31 model hashes match `PROVERIF_MODEL_SHA256` | 493 s / 1 177 s |
| `linux-full` (119817852433) | success | job 3 h 31 m (`kat` 4 453 s, `coverage` 4 171 s, `miri` 2 956 s, `nextest` 622 s) |
| `mutants` secmp-crypto / proto / relay / client-core / transport | caught 171 / 857 / 438 / 530 / 341; missed 1 / 3 / 0 / 8 / 4 (three undocumented, killed in `2f71140`) | shards 1 h 29 m – 2 h 31 m |
| `windows-native` | success (run 39939400878, job 120366845842): clippy, nextest, doctest, kat, hello PASS; nextest 1074 + 162 passed, kat harness 280 passed (16 skipped) | job 47 min 37 s (`kat` 1 866 s, `nextest` 799 s) |

## Bandwidth

Bytes on the wire of the link layer (4 352-B frames), without Tor, per scenario (Strict 1 contact, Balanced 4, Low-bw 5) steady state (MR-01, 24 virtual hours;
`M6-evidence/MR-01.txt`):

| mode (scenario) | model, B/s | measured, B/s while up | error | measured, MB/day |
|---|---|---|---|---|
| Strict (1 contact, P = 10 s) | 3 046.4 | 3 045.9 | 0.017 % | 263.2 |
| Balanced (4 contacts, P = 10 s, T = 10 s) | 4 787.2 | 4 786.3 | 0.019 % | 413.5 |
| Low-bw (5 contacts, P = 40 s, T = 30 s) | 1 595.7 | 1 594.7 | 0.065 % | 137.8 |

With Tor, model only (spec §10.2: a 4 352-B frame is 9 cells of 514 B = 4 626 B on a circuit, +6.3 %): Strict 3 238 B/s
(279.8 MB/day), Balanced 5 089 B/s (439.7 MB/day), Low-bw 1 696 B/s (146.6 MB/day). These are `model` values derived
from the table above; the measured ones are MR-04: not measured — owner-operated (two machines over real Tor), 2026-10-22.
The Strict figure keeps the ADR-018 constraint of at most ≈ 300 MB/day per contact (263.2 MB/day without, 279.8 MB/day with the
modelled Tor overhead).

## Tor overhead

- Model (spec §10.2, 9 cells × 514 B = 4 626 B per frame): +6.3 %.
- Measured bytes on the wire per 4 352-B frame over real Tor (MR-04, Strict P = 10 s and Balanced 4 contacts, ≥ 100 messages each way):
  not measured — owner-operated, two machines over real Tor, 2026-10-22.
- Cold bootstrap of Arti without `compression` (MR-07, ADR-051): bootstrap_seconds=9.2 bytes_down=41751578 (≈ 41.8 MB; `tor-smoke` run 39942840603, head `60083af`, ubuntu-latest, 2026-10-23; `M6-evidence/tor-smoke-39942840603.txt`; includes the runner's background traffic).

## Latency over Tor

- Model: a message waits up to one period `P_q` in the sender's queue and up to one period at the recipient before the next fetch;
  plausibility bound for the measurement (MR-04): p95 ≤ 2·P + 20 s = 40 s (Strict, P = 10 s).
- Measured median / p95 / max over real Tor (MR-04): not measured — owner-operated, two machines over real Tor, 2026-10-22.

## CPU

Preparation of one cell (TR encrypt + persist + seal), 10 000 slots, container `secmp-main`
(`M6-evidence/MR-05.txt`): **median 311.8 µs, p99 341.5 µs, max 1 122.7 µs** (the quietest of exactly three rounds of 10 000 slots, run alone: p99 341.5 / 343.6 / 341.6 µs); the M3 bound is 3 000 µs (p99 < 3 000 µs: met). The test runs alone under nextest (ADR-047 Am. 8).
The CI `perf` step of run #176 (`linux-full`, encrypt + persist + decrypt + commit, 200 messages per kind) gives chain
median 199.9 µs / max 261.0 µs and DH-step median 544.1 µs / max 616.3 µs.

Share of a core over one virtual hour (whole rig, upper bound):

| mode | wall time for 1 h of virtual time | share of a core |
|---|---|---|
| Strict, 1 contact | 1 099 ms | 0.03 % |
| Balanced, 4 contacts | 1 635 ms | 0.04 % |
| Low-bw, 5 contacts | 585 ms | 0.01 % |

Windows VM (MR-05 VM part): not measured — owner-operated Windows 11 VM, 2026-10-22. GitHub `windows-latest` (`windows-native`,
run 39939400878): `cpu_per_slot_measured` PASS (p99 < 3 000 µs, best of three rounds) in 11.2 s; the runner's figures are not in the log and no artefact is uploaded, so no µs value is quoted.

## Drain 1 h/24 h

After the recipient was offline (MR-02, `M6-evidence/MR-02.txt`; the relay keeps 128 cells per queue):

| case | sent | evicted | drained in | bound |
|---|---|---|---|---|
| Strict, 1 h offline, P = 10 s | 360 | 232 | 42 receive ticks | ≤ 45 |
| Strict, 24 h offline | 8 640 | 8 512 | 42 receive ticks | ≤ 45 |
| Balanced, 4 senders × 10 s, 1 h | 1 470 | 958 | 126 slots | ≤ 130 |
| Low-bw, 5 senders × 40 s, 24 h | 10 802 | 10 162 | 149 slots | ≤ 153 |

The relay keeps 128 cells per queue; what the senders sent beyond that is evicted by the relay, and no real message is lost
(`drain_after_offline_virtual`).

## Recommendation (ADR-018)

ADR-018 stays **"Proposed (owner decides after M6)"**; the table is the executor's reading of the measurements for the owner.

| parameter | provisional value (spec §4.2) | measured cost | §10.1 check | recommendation |
|---|---|---|---|---|
| `PERIODS` | {10, 20, 40, 80} s | Strict 3 045.9 B/s = 263.2 MB/day per contact at P = 10 s (measured); at 20 / 40 / 80 s ½ / ¼ / ⅛ of it (model, the rate is ∝ 1/P) | AI-01…AI-06: max \|Δt\| = 0 ms on both directions, 64 traces × 6 h; AI-10 / AI-07 loopback part: KS test of the departure gaps (`ks-hour`, dispatch); AI-07 loopback: MET, run 39942819176 (analyser of `60083af` shape-checked the 4 long links, 5 678 frames; 24 units on 8 pool control connections (QUEUE_NEW one-shots) plus 8 long-link handshake units were outside the C2-12 shape check; control slots are checked separately from C2-18c (C2-18b's mechanism left the set empty on a real run); first real evidence from the `ks-hour` re-run (C2-19); re-run of `ks-hour` on the fixed head requested, owner dispatch) | keep |
| `T_BALANCED` | 10 s | 4 786.3 B/s = 413.5 MB/day for 4 contacts (measured) | AI-02; Balanced KS in `ks-hour`: frames per departure constant 2 | keep |
| `T_LOWBW` | 30 s | 1 594.7 B/s = 137.8 MB/day for 5 contacts (measured) | AI-03 | keep |
| `F` | 4 cells per `FETCH` | Strict: queue drained in 42 receive ticks after 24 h offline (bound 45) | drain is part of the fixed slot, no extra operation | keep |
| `F_M` | 8 cells per `FETCH_MULTI` | Balanced 126 slots (bound 130); Low-bw 149 slots (bound 153) | `Σ 1/P_q ≤ F_M / (2·T)` enforced by `rate_bound_ok` | keep |
| `P_POOL` | 80 s | model: a pool queue is one recv queue at 80 s, 5 frames per 80 s = 23.5 MB/day per spare (no separate capture; the pool is on in every MR-01 scenario) | `pool_queue_never_idles_out` | keep |

All values keep the activity-independence invariant (§10.1) and the ≈ 300 MB/day Strict limit (263.2 MB/day measured, 279.8 MB/day
with the modelled Tor overhead). Two inputs of the decision are still open: the Tor overhead and latency (MR-04) and the Windows CPU
(MR-05 VM part); the recommendation is "keep the provisional values" unless MR-04 shows a Tor overhead well above 7 % or a p95 above 40 s.

## Gaps

| item | status |
|---|---|
| MR-04 Tor overhead and latency over real Tor ⚙ | not measured — owner-operated, two machines over real Tor, 2026-10-22 |
| MR-05 VM part, process CPU % on the Windows 11 VM ⚙ | not measured — owner-operated Windows 11 VM, 2026-10-22 |
| AI-07 Tor part, TC-07, TC-08, TOR-10 ⚙ | not measured — owner-operated, 2026-10-22 |
| `windows-native` numbers of run #176 | void (stack overflow, fixed in `1769900`); replaced by run 39939400878 (`M6-evidence/ci-run-182-windows.txt`); Windows µs figures not quoted — not in the log, 2026-10-23 |
| ct figures of run #176 | the job passed, its step summary is not in the log; no figure quoted |
| per-spare cost of the pool queue (`P_POOL`) | model value only; no separate capture |
