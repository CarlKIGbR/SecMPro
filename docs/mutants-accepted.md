# Accepted mutation survivors

`docs/06` §4: `cargo mutants` on `secmp-crypto`, `secmp-proto`, `secmp-relay`, `secmp-client-core` and `secmp-transport` (ADR-047 Amendments 3 and 4) must leave **zero surviving mutants, or each
survivor documented here** with the reason it cannot be detected by a test. Every entry names the mutant as
`cargo mutants` prints it in `missed.txt`/`timeout.txt` (`<path>:<line>:<column>: <description>`): its place as
`` `<path>:<line>` `` (`` `<path>:<line>:<column>` `` where two survivors share a line) and its description in backticks,
and the milestone that accepted it. The gate (`xtask/src/gates.rs`, `undocumented_survivors`) accepts a survivor only
when one row names both its place and its description (M5 review R-114, C-7), so the same mutation elsewhere in the
file is not accepted. A row whose code moves is updated to the new line; an entry is removed when the code changes.

| Mutant | Why no test can detect it | Compensating control | Accepted in |
|---|---|---|---|
| `crates/secmp-crypto/src/secret.rs:59`: `replace <impl Drop for SecretBytes<N>>::drop with ()` | Zeroisation on drop: after `drop` the heap allocation is freed; reading it again is undefined behaviour, so no sound test can observe whether the bytes were overwritten. | The zeroising `Drop` is two lines calling `zeroize::Zeroize` (volatile writes + compiler fence); the zeroising step itself is unit-tested (`secret::tests::secret_bytes_zeroise_on_drop_step`); long-lived secrets use `LockedSecret`, whose `SecretPage` zeroises before `munmap`/`VirtualFree` (its `Drop` is outside the mutated crates). | M1 |
| `crates/secmp-proto/src/inv.rs:163:32`: `replace | with ^ in base64url_encode` | Equivalent mutant (the first `\|`): in `(b0 << 16) \| (b1 << 8) \| b2` the three operands occupy disjoint bit ranges (bits 16..24, 8..16, 0..8; each byte is at most 0xff), so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `inv::tests::base64url_vectors` checks the whole encoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:163:44`: `replace | with ^ in base64url_encode` | Equivalent mutant (the second `\|` of the same expression): the operands are disjoint as above, so `\|` and `^` give the same value on every input. | As above. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:202`: `replace | with ^ in base64url_decode` | Equivalent mutant: in `(group << 6) \| (v & 0x3f)` the shifted operand has bits 0..6 clear and the appended one has only bits 0..6 set, so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `base64url_vectors` checks the decoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-client-core/src/scheduler/core/mod.rs:1695:21`: `delete match arm State::Up(up) in Scheduler::work_pass` | Unreachable defensive branch: it runs only when `World::outcome` returns `Ok(false)`, which it does for a (request kind, outcome) pair the channel never produces — `Channel` derives the expected outcome from the command it sealed, so no relay input reaches it. | The pair match in `World::outcome` (`_ => return Ok(false)`) and `Channel::finish` tests (TEST-SPEC-M6 CH-*). | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/core/mod.rs:1695:44`: `replace == with != in Scheduler::work_pass` | Same branch as above (the link lookup `up.id == p.link` inside the unreachable `Rejected` teardown). | As above. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tls.rs:366:13`: `replace \|\| with && in <impl StreamProvider for TlsProvider<D>>::connect` | Belt-and-braces check after the handshake: the client configuration offers TLS 1.3, the `X25519MLKEM768` group and ALPN `secmp/1` only, so rustls ends a deviating handshake with an error (`Rejected`) before the check sees the session; with the mutation all 36 `secmp-transport` tests incl. TLS-04/-09 still pass. | TLS-04, TLS-09 (the handshake itself refuses); `tls_provider_is_explicit` (TLS-10). | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tor/mod.rs:53:26`: `replace \| with ^ in base32` | Equivalent mutant: in `(acc << 8) \| u16::from(b)` the accumulator was masked to fewer than 5 bits and shifted by 8, the byte has only the low 8 bits: the operands are disjoint, so `\|` and `^` agree on every input. | `base32_follows_rfc4648`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-transport/src/tor/mod.rs:60:23`: `replace << with >> in base32` | Equivalent mutant: `acc &= (1 << bits) - 1` only clears bits above `bits` that the next `(acc >> bits) & 0x1f` window and the `u16` shift by 8 never read; the mutation (no mask) gives the same output for every input — checked against a bit-string reference for every length 0…40 bytes. | As above. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/run.rs:843:34`: `replace > with >= in Driver<P, D, R, H, W, C>::flush_wait` | Equivalent mutant: `io.oldest` is `Some` exactly while `io.pending > 0` (it is set with the first pending write and cleared when the count returns to 0), so `pending >= 0 && oldest == Some(now)` selects the same links. | `flush_wait_ends_at_the_completion_of_the_pass_writes`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-client-core/src/scheduler/run.rs:1027:54`: `replace > with >= in Driver<P, D, R, H, W, C>::apply` | Equivalent mutant for the same reason (`pending >= 0 && oldest.is_some_and(..)`). | `driver_closes_a_link_whose_write_is_pending_at_its_next_tick`. | M6 (WEISUNG M6-CI-9) |
| `crates/secmp-relay/src/tls.rs:198:9`: `replace <impl Write for Deadlined<S>>::flush -> io::Result<()> with Ok(())` | rustls's `StreamOwned` and `complete_io` never call `flush` on the socket (the TLS records are written with `write_tls`); the method only satisfies the `Write` bound of the socket parameter. | `any_conn_delegates_to_its_connection` for the other wrappers; the write path is covered by the direct-TLS tests. | M6 (WEISUNG M6-CI-9) |

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
