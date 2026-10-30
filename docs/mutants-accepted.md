# Accepted mutation survivors

`docs/06` §4: `cargo mutants` on `secmp-crypto`, `secmp-proto`, `secmp-relay`, `secmp-client-core`, `secmp-transport` and `secmp-store` (ADR-047 Amendments 3, 4 and 10) must leave **zero surviving mutants, or each
survivor documented here** with the reason it cannot be detected by a test. Every entry names the mutant as
`cargo mutants` prints it in `missed.txt`/`timeout.txt` (`<path>:<line>:<column>: <description>`): its place as
`` `<path>:<line>` `` (`` `<path>:<line>:<column>` `` where two survivors share a line) and its description in backticks,
and the milestone that accepted it. The gate (`xtask/src/gates.rs`, `undocumented_survivors`) accepts a survivor only
when one row names both its place and its description (M5 review R-114, C-7), so the same mutation elsewhere in the
file is not accepted. A row whose code moves is updated to the new line; an entry is removed when the code changes.

| Mutant | Why no test can detect it | Compensating control | Accepted in |
|---|---|---|---|
| `crates/secmp-crypto/src/secret.rs:59`: `replace <impl Drop for SecretBytes<N>>::drop with ()` | Zeroisation on drop: after `drop` the heap allocation is freed; reading it again is undefined behaviour, so no sound test can observe whether the bytes were overwritten. | The zeroising `Drop` is two lines calling `zeroize::Zeroize` (volatile writes + compiler fence); the zeroising step itself is unit-tested (`secret::tests::secret_bytes_zeroise_on_drop_step`); long-lived secrets use `LockedSecret`, whose `SecretPage` zeroises before `munmap`/`VirtualFree` (its `Drop` is outside the mutated crates). | M1 |
| `crates/secmp-proto/src/inv.rs:163:32`: `replace \| with ^ in base64url_encode` | Equivalent mutant (the first `\|`): in `(b0 << 16) \| (b1 << 8) \| b2` the three operands occupy disjoint bit ranges (bits 16..24, 8..16, 0..8; each byte is at most 0xff), so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `inv::tests::base64url_vectors` checks the whole encoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:163:44`: `replace \| with ^ in base64url_encode` | Equivalent mutant (the second `\|` of the same expression): the operands are disjoint as above, so `\|` and `^` give the same value on every input. | As above. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:202`: `replace \| with ^ in base64url_decode` | Equivalent mutant: in `(group << 6) \| (v & 0x3f)` the shifted operand has bits 0..6 clear and the appended one has only bits 0..6 set, so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `base64url_vectors` checks the decoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-client-core/src/scheduler/core/mod.rs:1737:21`: `delete match arm State::Up(up) in Scheduler::work_pass` | Unreachable defensive branch: it runs only when `World::outcome` returns `Ok(false)`, which it does for a (request kind, outcome) pair the channel never produces — `Channel` derives the expected outcome from the command it sealed, so no relay input reaches it. | The pair match in `World::outcome` (`_ => return Ok(false)`) and `Channel::finish` tests (TEST-SPEC-M6 CH-*). | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/core/mod.rs:1737:44`: `replace == with != in Scheduler::work_pass` | Same branch as above (the link lookup `up.id == p.link` inside the unreachable `Rejected` teardown). | As above. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tls.rs:366:13`: `replace \|\| with && in <impl StreamProvider for TlsProvider<D>>::connect` | Belt-and-braces check after the handshake. The mutant is the *second* `\|\|` (line 366, in front of the protocol-version disjunct): the condition becomes `alpn != ALPN \|\| (group != GROUP && version != TLS13)`. The ALPN disjunct stays intact, and a missing or wrong ALPN is refused by that retained explicit check (TLS-09), not by the handshake — a server may finish a handshake without ALPN. Only the group and version disjuncts are weakened, and they cannot be true after a successful handshake: the client configuration offers TLS 1.3 and the `X25519MLKEM768` group only, so rustls ends a deviating handshake with an error (`Rejected`) before the check sees the session; with the mutation all 36 `secmp-transport` tests incl. TLS-04/-09 still pass. | TLS-04, TLS-09 (the handshake itself refuses); `tls_provider_is_explicit` (TLS-10). | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tor/mod.rs:53:26`: `replace \| with ^ in base32` | Equivalent mutant: in `(acc << 8) \| u16::from(b)` the accumulator was masked to fewer than 5 bits and shifted by 8, the byte has only the low 8 bits: the operands are disjoint, so `\|` and `^` agree on every input. | `base32_follows_rfc4648`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tor/mod.rs:60:23`: `replace << with >> in base32` | Equivalent mutant: `acc &= (1 << bits) - 1` only clears bits above `bits` that the next `(acc >> bits) & 0x1f` window and the `u16` shift by 8 never read; the mutation (no mask) gives the same output for every input — checked against a bit-string reference for every length 0…40 bytes. | As above. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/run.rs:859:34`: `replace > with >= in Driver<P, D, R, H, W, C>::flush_wait` | Equivalent mutant: `io.oldest` is `Some` exactly while `io.pending > 0` (it is set with the first pending write and cleared when the count returns to 0), so `pending >= 0 && oldest == Some(now)` selects the same links. | `flush_wait_ends_at_the_completion_of_the_pass_writes`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/run.rs:1050:54`: `replace > with >= in Driver<P, D, R, H, W, C>::apply` | Equivalent mutant for the same reason (`pending >= 0 && oldest.is_some_and(..)`). | `driver_closes_a_link_whose_write_is_pending_at_its_next_tick`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/core/mod.rs:755:39`: `replace \|\| with && in World::prepare_fetch` | Unreachable: `members.is_empty() \|\| members.len() > FETCH_MULTI_LIMIT` is reached only for a relay link, and `prepare_link` calls `prepare_fetch` for a relay link only when `self.recvs.iter().any(\|q\| q.relay == r)` (never empty), and `check_balanced` refuses a 33rd recv-queue on a relay (`TooManyQueues`), so neither side of the `\|\|` can be true there. The `>` bound itself is killed (`prepare_fetch_takes_exactly_thirty_two_queues`). | `prepare_fetch_takes_exactly_thirty_two_queues`; `balanced_fetch_multi_lists_all_recv_queues` (the 33rd queue is refused). | M6 (WEISUNG M6-C1-3) |
| `crates/secmp-client-core/src/scheduler/core/pure.rs:84:30`: `replace > with >= in Received<N>::record` | Equivalent mutant: the search for the insertion slot runs only after `position(id)` found no recorded entry equal to `id`, so no recorded id equals `id` there and `*x > id` and `*x >= id` pick the same slot. | `pure::tests::a_full_ledger_keeps_the_ack_below_what_it_could_not_record` (insertion keeps the ids ascending), `refetch_hands_over_only_what_is_not_committed`. | M7 (WEISUNG M7-B-SC) |
| `crates/secmp-transport/src/channel.rs:486:9`: `delete match arm ResponseCmd::Err(_) in single` | Equivalent mutant: the arm answers `Err(Rejected)` for an `ERR` code the command does not allow; without it the `ERR` falls to `other if ok(&other)` (no `ok` closure accepts an `ERR`) and then to `_ => Err(Rejected)`, the same result for every input. | `channel_finish_rejects_misfit_send_answers` (the `ERR` of a wrong code is refused). | M6 (WEISUNG M6-C1-3) |
| `crates/secmp-store/src/wrap.rs:133:9`: `replace Unlocked::lock with ()` | Equivalent mutant: `lock(self)` takes the `Unlocked` by value, so it is dropped at the end of the call whether the body is `drop(self)` or empty; every key it holds is a `StoreKey`, whose `LockedSecret` zeroizes its page on drop either way. | `secrets::tests::long_lived_keys_in_secret_pages` (ST-19): `kat::live_key_pages()` = 0 after `lock()` | M7 (A-4) |

History (M1, first full run, 2026-09-28: 241 mutants, 149 caught, 86 unviable, 6 missed): besides the entry above,
the missed mutants were fixed rather than accepted — an unused `kat` helper (`Caead::commitment_kat`) was removed;
the equivalent `<`/`<=` mutant in `ed25519::strict::less_than` disappeared with a `cmp`-based comparison; the
byte-level signature checks of `Ed25519VerifyingKey::verify` (which `ed25519-dalek` duplicates, so an end-to-end
test cannot see them) moved into `strict::signature_ok` with direct unit tests; the redundant `% 100000` in the SAS
digit conversion (equivalent to the five-digit extraction that follows) was removed.

M5 (review 2026-10-09, R-114/R-163, C-7): the two `secmp-relay` rows of Phase B (`server.rs:81`
`<impl Stream for TcpStream>::set_poll` and `server.rs:86` `<impl Stream for TcpStream>::close`) were removed — not
equivalent (`set_poll`'s read timeout carries the 30-s pre-HELLO bound); a loopback test kills both.

## Rules

- **Timeouts (M6, WEISUNG M6-B-4 §0.2).** A mutant that times out at the second run's 900 s inside a loop of the
  scheduler or the transport — `World::tick`, `poll_due`, `accept_ceiling`, `find` — counts as caught-by-hang: the
  mutation makes the loop not terminate, which the test run detects. Every other timeout, and every missed mutant,
  needs a killing test or a row in the table above with its reason.

## Excluded

Files kept out of the mutation gate (`expect::MUTANT_EXCLUDE_FILES`), each with its reason. ADR-047 Amendment 4: only
Kani-only files and files of pure Arti/rustls glue that need a live network may be listed; a glue file is named here in
backticks with the reason before it enters the list.

| File | Reason |
|---|---|
| `crates/secmp-proto/src/kani_proofs.rs` | Compiled only under `cfg(kani)`; no test build contains it; Kani runs it. |
| `crates/secmp-relay/src/kani_proofs.rs` | As above. |
| `crates/secmp-client-core/src/kani_proofs.rs` | As above (K-01…K-07, `cfg(kani)`; ADR-047 Am. 4; PR run 38724110285). |
| `crates/secmp-transport/src/tor/arti.rs` | Pure Arti glue that needs a live Tor network (BRIEF M6-B §2.5): creating the Arti client, its bootstrap, the follower that reads Arti's bootstrap status, and `connect_with_prefs` to the onion service. No test may reach the network (`docs/06` §4), so every mutant there would survive. It decides nothing; the rules are in `tor/mod.rs` and its tests (TOR-01…TOR-09, FZ-03), which stay in the gate. The owner-operated rows TOR-10 and X-10 run it against Tor. |

## Skipped

Tests left out of the test run of every mutant (`expect::MUTANT_SKIP_TESTS`, ADR-047 Amendment 1 (5);
`expect::MUTANT_HARNESS_SKIP_TESTS`, ADR-047 Amendment 4, second run). They run in the `kat` and `nextest` steps on every
PR. Runtimes: nextest on the 32-core container, 2026-10-15 (harness) and the CI figures of Amendment 1 (proto).

| Test | Package / suite | Measured runtime | List |
|---|---|---|---|
| `ratchet_fast_forward_bound_on_the_chain` | `secmp-proto` `tr::tests` (kat) | 49–110 s on CI | `MUTANT_SKIP_TESTS` |
| `ratchet_fast_forward_bound_on_a_step` | `secmp-proto` `tr::tests` (kat) | 37–73 s on CI | `MUTANT_SKIP_TESTS` |
| `activity_independence_balanced_virtual` (AI-02) | `secmp-testkit` harness | 226 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `activity_independence_strict_virtual` (AI-01) | `secmp-testkit` harness | 203 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `activity_independence_lowbw_virtual` (AI-03) | `secmp-testkit` harness | 184 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `bandwidth_model_matches_capture` (MR-01) | `secmp-testkit` harness | 159 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `pool_queue_never_idles_out` (QP) | `secmp-testkit` harness | 88 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `activity_independence_both_directions` (AI-05) | `secmp-testkit` harness | 62 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `activity_independence_when_receiving` (AI-04) | `secmp-testkit` harness | 60 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `drain_after_offline_virtual` (MR-02) | `secmp-testkit` harness | 52 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai_asymmetric_prepare_cost_does_not_move_emission` (AI) | `secmp-testkit` harness | 24 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `prop_schedule_independent_of_activity` (property) | `secmp-testkit` harness | 21 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai01_strict_tokio` (AI-01, tokio driver) | `secmp-testkit` harness | 49 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai02_balanced_tokio` (AI-02, tokio driver) | `secmp-testkit` harness | 31 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai03_lowbw_tokio` (AI-03, tokio driver) | `secmp-testkit` harness | 25 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai04_when_receiving_tokio` (AI-04, tokio driver) | `secmp-testkit` harness | 40 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai05_timing_draws_tokio` (AI-05, tokio driver) | `secmp-testkit` harness | 39 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai06_both_directions_tokio` (AI-06, tokio driver) | `secmp-testkit` harness | 43 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `ai07_fault_paired_tokio` (AI-07, tokio driver, fault-paired) | `secmp-testkit` harness | 5 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `timing_draws_independent_of_activity` (AI-05; TEST-SPEC-M7 G7-09, split, killer: `timing_draws_unmoved_by_one_hour_of_activity` — the same scenario over 1 h with one trace, kept in the per-mutant run) | `secmp-testkit` harness | 69.5 s (C2-18c) | `MUTANT_HARNESS_SKIP_TESTS` |
| `relay_idle_and_age_bounds_from_schedule` (G-12; TEST-SPEC-M7 G7-09, split, killer: `relay_idle_and_age_bounds_defaults` — the idle and age bounds of the relay defaults, kept in the per-mutant run) | `secmp-testkit` harness | 27 s (C2-18c) | `MUTANT_HARNESS_SKIP_TESTS` |
| `crash_between_persist_and_send_no_key_reuse` (PC-05; TEST-SPEC-M7, A-3: 5 crash points × 20 seeds, two child processes each) | `secmp-testkit` harness | 244 s | `MUTANT_HARNESS_SKIP_TESTS` |
| `write_amplification_measured` (PC-13; TEST-SPEC-M7, A-3: 24 h virtual over two SQLCipher profiles, one fsync per commit) | `secmp-testkit` harness | 295 s | `MUTANT_HARNESS_SKIP_TESTS` |
