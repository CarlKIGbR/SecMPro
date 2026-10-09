# TEST-SPEC-M6 — transport providers, constant-rate scheduler, measurements (planner draft v1, 2026-10-09)

For the implementer, dictated by the reviewer (attachment of BRIEF_M6, all phases). Sources: `docs/03-protocol-spec.md`
rev 2.6 (`docs/03:<line>` = line of that file at `main` 6300b65), `docs/07-milestones.md` §M6 (`docs/07:119-133`),
`docs/02` §3, §4.1, §4.4, `docs/04` CS-3.6, `docs/05` §2, §7, `docs/06` §2–§5, `docs/08` ADR-007, ADR-009, ADR-018,
ADR-024, ADR-036, ADR-037, ADR-047, ADR-049, ADR-050, `docs/reviews/M05-review.md` §C/§H (F-M6 rows), the M5 fix
verification `VD-M5-FIX.md` (convo.rs mutants). Companion files: `OPEN-M6.md` (questions OPEN-M6-01…26 with defaults),
`ADR-051-proposed.md`, `BRIEF_M6-draft.md`. Form: `TEST-SPEC-M5.md`.

## Counts

| Section | Rows | Phase A (Sonnet) | Phase B (Opus) | Phase C (Sonnet) |
|---|---|---|---|---|
| (a) `transport::tor` | 10 | 0 | 10 | 0 |
| (b) `transport::tls` + relay direct listener | 15 | 0 | 15 | 0 |
| (c) prepared frames, pipelining, async driver | 12 | 6 | 6 | 0 |
| (d) scheduler: LinkTask 32, ControlOps 8, QueuePool 5, outbox 8, rotation/back-off 6 | 59 | 59 | 0 | 0 |
| (e) `two-clients` binary | 9 | 0 | 0 | 9 |
| (f) turmoil simulations | 10 | 0 | 0 | 10 |
| (g) activity independence | 10 | 8 | 0 | 2 |
| (h) measurement report | 7 | 2 | 0 | 5 |
| (i) F-M6 follow-ups | 12 | 11 | 1 | 0 |
| (j) gates: Kani 7, property 7, fuzz 4, mutants 1, ct 1, ProVerif 1, coverage 2, xtask 10 | 33 | 17 | 12 | 4 |
| **total** | **177** | **103** | **44** | **30** |

⚙ = owner-operated (test relay with C tor, Windows 11 VM, a second machine, real Tor). ⚙ rows: TC-07, TC-08, AI-07
(Tor part), MR-04, MR-05 (VM part), X-10, TOR-10. Their non-availability path (CLAUDE.md §6 last bullet) is under
"Conventions" and binds every ⚙ row.

Markers: **[O-n]** = the row is built with the default of OPEN-M6-n (`OPEN-M6.md`); if the decision differs, the row is
re-dictated, never silently changed. **[DEP]** = needs the ADR-051 dependency set ratified by the owner and its
`cargo vet` records (named human) in the tree; such rows start in Phase B after the ratification commit. **[⚙]** as above.

## Conventions (apply to every row)

- **Clock.** `secmp_client_core::clock`: trait `Clock { fn mono_ms(&self) -> u64; fn unix_secs(&self) -> u64 }`,
  `SystemClock` (the sanctioned `SystemTime::now`/`Instant::now` site, `docs/06` §2), `ManualClock` (virtual, ms
  resolution). Every time in a row is virtual milliseconds unless it says "real". No row reads a wall clock (`docs/06`
  §4), except the ⚙ rows and AI-07.
- **Two entropy streams.** `TimingRng` (link phases, lifetimes, control-op delays, re-creation delays, back-off) and the
  content entropy (TR, HX, signatures, padding, `msg_id`). A kat build seeds both from `(suite, actor)` like
  `EntropyPool`. "Same seed" in a row means the same `TimingRng` seed; content seeds may differ.
- **Uniform draws.** `U[a, b]` ms = rejection sampling on 64-bit draws from `TimingRng` (no modulo bias), inclusive bounds.
  Distribution rows use 1 000 seeded draws and a one-sample KS test against the uniform CDF with `p ≥ 0.01`; the
  assertion message carries D and p.
- **Parameters** (`scheduler::Params::default()` = `docs/03` §4.2 provisional values, ADR-018): `PERIODS` = {10 000,
  20 000, 40 000, 80 000} ms; `T_BALANCED` = 10 000; `T_LOWBW` = 30 000; `F` = 4; `F_M` = 8; `PHASE_MAX` = 180 000;
  `LIFETIME` = [21 600 000, 86 400 000]; `MAX_IN_FLIGHT` = 2; `CONTROL_DELAY` = [60 000, 3 600 000]; `RECREATE_DELAY` =
  [10 000, 300 000]; `FETCH_LEAD` = 1 000 [O-13]; `BACKOFF_CAP` = 3 600 000 [O-14]; `P_POOL` = 80 000 [O-17].
- **Rate bound in integers** (§10.2 `:662-663`): Balanced accepts a recv-queue set iff Σ_q 80 000/P_q ≤ 32 (= Σ 1/P ≤
  F_M/(2·T_BALANCED) · 80 s); Low-bw iff Σ_q 240 000/P_q ≤ 32 (= Σ 1/P ≤ 8/60 · 240 s). Pool queues count toward the
  32-entry `FETCH_MULTI` limit, not toward the rate bound [O-17].
- **Trace.** `Trace = Vec<(t_ms, len, dir, link_slot)>`, one entry per record or frame the client writes (`dir` = C2R)
  or reads (`dir` = R2C); `link_slot` is the index of the link in creation order, not an id. Handshake record lengths
  (D.1): HELLO 9, RELAYINFO 1 744, HS1 2 856, HS2 1 156; every later unit 4 352.
- **Tick anchoring [O-12].** A scheduled link's tick k ≥ 1 is at `t_up + k·P` (Strict: `P = P_q`; Balanced:
  `T_BALANCED`; Low-bw: `T_LOWBW`), `t_up` = the instant HS2 was accepted; nothing is written at `t_up` itself. The link
  closes at `t_up + L` (L = its lifetime): no unit is written at or after it.
- **Prepared frame.** The 4 352-B sealed frame (request built, signed, padded, sealed under `k_c2r` at its counter) plus,
  for SEND, the cell whose ratchet step was persisted before sealing. `tick()` writes prepared bytes only.
- **Counting accessors (kat).** `seal_calls`, `tr_encrypt_calls`, `sign_calls`, `persist_calls`, `timing_draws` —
  counters on the kat build, read before/after a unit, like M4's counting `Entropy`.
- **Local events** (`LinkEvent`): `Up`, `TornDown(Reason)` with `Reason ∈ {InFlight, Overrun, Lifetime,
  NewLinkRequired, Closed, ClosedBeforeRelayInfo, Rejected, ModeChange}`; `Alert(QueueAuth | QueueRate)`. None reaches
  the wire.
- **API sketch (proposal; names may change, test names may not):** `secmp_transport::session::Session::{prepare(req) ->
  Result<Prepared>, write_prepared(&Prepared), read_response(&Pending) -> Result<Response>}`; `secmp_transport::driver::
  {AsyncSession, AsyncRelayQueueTransport, StreamProvider, IsolationKey}`; `secmp_transport::{tor::TorProvider,
  tls::TlsProvider}`; `secmp_client_core::scheduler::{core::{Scheduler, LinkTask, LinkKind, Mode, Params}, control::
  ControlOps, pool::QueuePool, outbox::{Outbox, MemOutbox, Persist, MemPersist}, run (tokio driver)}`;
  `secmp_testkit::{VirtualDriver, two_clients}`.
- **IDs.** TOR, TLS (a, b) · AD (c) · S scheduler core, CO ControlOps, QP QueuePool, OB outbox, LR rotation/reconnect/
  back-off (d) · TC (e) · SIM (f) · AI (g) · MR (h) · G (i) · K, P, FZ, MU, CT, PV, COV, X (j). "Ph" = phase.
- **⚙ non-availability path.** A ⚙ row whose infrastructure is unavailable is not faked and not replaced silently: the
  report lists it under "Blocked — owner infrastructure" with the date asked, everything else of the milestone is
  delivered, and the row stays open in the review (the reviewer may accept the named substitute evidence only with the
  owner's written consent, OPEN-M6-20). Substitutes: TC-07/TC-08 → TC-05/TC-06 + `tor-smoke` dispatch run; AI-07 Tor
  part → AI-07 loopback part; MR-04 → none (reported "not measured"); MR-05 VM part → GitHub `windows-latest` numbers;
  X-10 → `windows-native` job (non-network tests) + `tor-smoke` on `windows-latest`.

## (a) `secmp-transport::tor` — Arti client (§8.1, §12.3; ADR-007, ADR-024; CS-3.6)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| TOR-01 | `tor_config_uses_profile_state_dir` [DEP] | §12.3 `:752`; CS-3.6 | `TorProvider::config(profile_dir = D)` | state dir `D/tor/state`, cache dir `D/tor/cache` (the two paths of the built `TorClientConfig`); `fs-mistrust` checks not disabled (no `dangerously_trust_everyone`) | Arti's default user dirs are used, or permission checks are switched off | B |
| TOR-02 | `tor_isolation_token_per_link` [DEP] | §8.1 `:525`; §12.3 | open 3 scheduled links and 2 one-shot links through a recording `StreamProvider` shim around `TorProvider` | 5 `connect` calls with 5 pairwise-distinct `IsolationToken`s in their `StreamPrefs`; a reconnect of link 1 uses a 6th token | any token is shared, cached per relay, or reused after a close | B |
| TOR-03 | `tor_no_link_before_bootstrap` [DEP] | §12.3 "No link is opened before Tor has bootstrapped"; CLAUDE.md §1.5 | mock bootstrap status 0 %, 50 %, 99 %, then ready | `connect` before ready → `Error::TorNotReady`, 0 streams opened, 0 bytes written; after ready → 1 stream | a stream is opened (or a HELLO written) before "ready" | B |
| TOR-04 | `tor_bootstrap_events_mapped` [DEP] | §12.3 | Arti bootstrap status sequence fraction 0.0, 0.5, 1.0 (ready), then a blockage | `TorEvent::Progress(0)`, `Progress(50)`, `Ready`, `Blocked` in this order, nothing else | an Arti status is dropped, reordered, or a percentage is computed differently | B |
| TOR-05 | `tor_never_falls_back_to_direct` [DEP] | CLAUDE.md §1.5; §5.3 `:231` | Tor mode; bootstrap error; then onion connect error; `RelayRef.direct` present | both surface `Error::TorUnavailable`; `TlsProvider::connect` call count 0; no TCP socket opened | any failure path reaches the direct provider | B |
| TOR-06 | `transport_selection_follows_user_choice_only` [DEP] | §5.3 `:231`; §8.1 | (direct setting, `RelayRef.direct`) = (off, present), (on, present), (on, absent) | Tor; TLS; `Error::NoDirectEndpoint` (no Tor attempt either) | the selection depends on anything but the explicit user setting and the RelayRef | B |
| TOR-07 | `arti_feature_set_is_pinned` [DEP][O-03] | ADR-024; ADR-051 | `cargo metadata` resolved features | `arti-client` features ⊇ {`onion-service-client`, `rustls`, `tokio`, `static-sqlite`} and contain neither `hs-pow-full`, `compression`, `native-tls`, `experimental` nor any `__is_experimental`; `tor-hsclient` has no `hs-pow-full` | `hs-pow-full` or an experimental/native-tls feature enters the graph | B |
| TOR-08 | `onion_address_from_relayref` [DEP] | §5.3 `:227`; rend-spec-v3 §6 | 35-B `onion` of a fixed test key (pk = 32 × 0x42) | `<56 lowercase base32 chars>.onion` equal to the independent encoding in the test (base32 of pk ‖ SHA3-256(".onion checksum" ‖ pk ‖ 0x03)[0..2] ‖ 0x03); Arti's `HsId` parse of it re-encodes to the same 35 B | our encoding differs from rend-spec-v3 or from Arti's parse | B |
| TOR-09 | `onion_connect_uses_port_443` [DEP][O-07] | §12.3; `docs/05` §2 torrc `HiddenServicePort 443` | recording shim | target = (`<onion>.onion`, 443) for every link | another port, or a DNS name, reaches Arti | B |
| TOR-10 | ⚙ `tor_bootstrap_and_link_windows_vm` [DEP] | `docs/07:131` | `cargo xtask win-test` on the owner's Windows 11 VM: Arti bootstrap, HELLO…HS2 + PING to the test relay onion | log shows `Ready`, `OK` to PING, the run id/date; committed under `docs/reviews/M06-evidence/` | Arti does not bootstrap on Windows or the link fails | B |

## (b) `secmp-transport::tls` and the relay's direct listener (§8.1 `:526`; `docs/05` §7; CLAUDE.md §1.3)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| TLS-01 | `tls_client_offers_exactly_x25519mlkem768` [DEP] | §8.1; CLAUDE.md §1.3 | `TlsProvider::client_config()`; ClientHello captured by an in-process rustls server | provider `kx_groups.len() == 1`, named group 0x11EC; ClientHello `supported_groups` = [0x11EC], `key_share` entries = [0x11EC] | a second group (X25519, P-256, …) is offered or shared | B |
| TLS-02 | `tls_client_is_tls13_only` [DEP] | §8.1 | in-process server limited to TLS 1.2 | handshake fails; 0 SecMP bytes written; client `supported_versions` = [0x0304] | TLS 1.2 is accepted | B |
| TLS-03 | `tls_no_classical_fallback` [DEP] | CLAUDE.md §1.2–1.3 | server groups [X25519]; [secp256r1]; server sends HelloRetryRequest for X25519 | all three fail; the client sends exactly one ClientHello; nothing after | a retry with a classical share happens | B |
| TLS-04 | `tls_handshake_with_pinned_relay_succeeds` [DEP] | §8.1; `docs/05` §7 | server: [X25519MLKEM768], TLS 1.3, ALPN `secmp/1`, fixture cert whose SPKI SHA-256 = pin | Ok; `negotiated_key_exchange_group()` = X25519MLKEM768; ALPN = `secmp/1`; then HELLO…HS2 + PING over it = OK | the pinned, compliant server is refused | B |
| TLS-05 | `tls_spki_pin_mismatch_rejects` [DEP] | §8.1; D.3 `spki_sha256` | pin with byte 0, byte 31 flipped; a second valid fixture cert | handshake fails, `Error::Rejected`, 0 SecMP bytes | a non-matching SPKI is accepted | B |
| TLS-06 | `tls_pin_is_the_only_trust_anchor` [DEP][O-09] | `docs/05` §7 "Web PKI is not used" | fixture certs: expired, not yet valid, wrong name, self-signed, each with the pinned SPKI; a CA-signed cert without the pin | the four pinned ones accepted; the CA-signed one rejected; chain length ≠ 1 rejected | dates/names decide, a CA store is consulted, or extra chain certs are accepted | B |
| TLS-07 | `tls_certificate_verify_still_checked` [DEP] | TLS 1.3 §4.4.3 | server presents the pinned cert but signs CertificateVerify with another key | handshake fails | the pin check replaces signature verification | B |
| TLS-08 | `tls_no_resumption_no_early_data` [DEP] | §8.1 "no tickets/resumption/0-RTT" | server issues 2 NewSessionTickets; second connection | client `resumption` disabled: session store holds 0 entries; the 2nd ClientHello has no `pre_shared_key`, no `early_data`; `enable_early_data == false` | a ticket is stored or offered, or 0-RTT is possible | B |
| TLS-09 | `tls_alpn_secmp1_required` [DEP] | §8.1 | server ALPN none; `h2` | both fail before any SecMP byte | the link runs without ALPN `secmp/1` | B |
| TLS-10 | `tls_provider_is_explicit` [DEP] | §8.1; CLAUDE.md §1.6 | install aws-lc-rs's default provider (≥ 3 groups) as the process default, then build our config | our config still has exactly 1 group (built with `builder_with_provider`); testscan: no `ClientConfig::builder()`/`ServerConfig::builder()` call in the workspace | the process-default provider leaks into our config | B |
| TLS-11 | `tls_link_bytes_equal_other_transports` [DEP] | §8.1 "identical SecMP-LINK bytes" | same kat entropy over TLS loopback and over the in-memory stream | HELLO, HS1 and the first 3 C2R frames byte-identical | the TLS path alters LINK bytes | B |
| TLS-12 | `relay_direct_tls_config` [DEP][O-08] | `docs/05` §7 | relay config `direct_tls = "127.0.0.1:0"`, fixture cert/key | server config: groups [X25519MLKEM768], TLS 1.3 only, ALPN [`secmp/1`], `send_tls13_tickets == 0`, `max_early_data_size == 0`, no client auth; listener absent when `direct_tls = ""` (default) | any of these differs, or the listener is on by default | B |
| TLS-13 | `relay_direct_tls_serves_link` [DEP][O-08] | `docs/02` §2; `docs/05` §7 | integration test (loopback, `docs/06:95`): client TLS → relay listener; with access key | HELLO…HS2, PING → OK, QUEUE_NEW → OK_QUEUE_NEW with derived ids | the listener does not carry the identical SecMP-LINK | B |
| TLS-14 | `relay_tls_refuses_classical_client` [DEP][O-08] | CLAUDE.md §1.3 | client with groups [X25519] | handshake fails; relay emits 0 SecMP bytes; the connection is released (`max_connections` count back to its value before) | the relay accepts a classical key exchange or leaks a slot | B |
| TLS-15 | `relay_spki_command_prints_pin` [DEP][O-09] | D.3 `spki_sha256` | `secmp-relay spki <fixture.der>` | prints the 64-hex SHA-256 of the SPKI DER, equal to the value computed in the test from the fixture's SPKI byte range | the printed pin is not the one clients check | B |

## (c) Prepared frames, pipelining, async driver (§10.1, §10.3, §12.1; ADR-050 (3); ADR-051)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| AD-01 | `prepare_seals_before_write` | §10.1 `:656` | `Session::prepare(SEND)` then `write_prepared` | `prepare`: `seal_calls` +1, c2r counter +1, 4 352 B; `write_prepared`: `seal_calls`, `sign_calls`, `tr_encrypt_calls`, `persist_calls` +0 and exactly 4 352 bytes written | any crypto or persistence runs on the write path | A |
| AD-02 | `prepared_frames_written_in_counter_order` | §8.4 `:567` | prepare A (ctr 0), B (ctr 1); write B first | `Error::OutOfOrder` (local), 0 bytes written; then A, B succeed | frames can leave out of counter order | A |
| AD-03 | `pipelined_responses_matched_in_order` | §10.3 `:678`; D.2 `:843` | SEND then FETCH outstanding; responses 1 + 4 frames | matched to SEND (OK_SEND) and FETCH (4 CELLR) in request order; outcomes as T-02/T-03 | responses are matched by arrival guess or reordered | A |
| AD-04 | `pipelined_mismatch_closes_link` | OPEN-M5-11 A | the response to request 1 carries request 2's `cmd_seq`; an OK_SEND where a FETCH's CELLR is due | `Error::Rejected`, link closed, nothing written after | a misfit response under pipelining is accepted | A |
| AD-05 | `frames_reassembled_from_any_chunking` | H-11 (M5) | stream delivers chunks of 1…4 352 B (seeded) | identical responses to the unchunked run | partial reads corrupt or drop a frame | A |
| AD-06 | `closed_before_relayinfo_is_its_own_outcome` | M05-review §H F-1 (M6 part) | relay closes after HELLO without RELAYINFO; a RELAYINFO that fails verification | `ConnectOutcome::ClosedBeforeRelayInfo`; `Error::Rejected` (§8.5 uniform otherwise) | the back-off (LR-04) cannot see the lockout case | A |
| AD-07 | `async_session_equals_sync_session` [DEP][O-01] | ADR-050 (3) | same kat entropy, `tokio::io::duplex` vs M5 `HarnessStream` | HELLO, HS1, link keys (kat), first 3 frames byte-identical | the async path diverges from the M5 session | B |
| AD-08 | `async_transport_matches_m5_outcomes` [DEP][O-10] | §12.1 `:731-743` | T-01…T-06 scenarios over `AsyncRelayQueueTransport` | outcomes and byte captures equal to the M5 synchronous runs | an operation's mapping changes | B |
| AD-09 | `queue_transport_async_signature` [DEP][O-10] | §12.1; ADR-051 | compile test | `AsyncQueueTransport` has the 7 §12.1 operations with `&mut self`, returns `impl Future + Send`; no `async-trait` crate in `Cargo.lock` | the trait loses an operation or pulls `async-trait` | B |
| AD-10 | `stream_provider_impls` [DEP] | §12.2 `:748` | compile test | `StreamProvider` implemented by `TorProvider`, `TlsProvider`, testkit `MemProvider`, testkit `TurmoilProvider`; the scheduler driver is generic over it | the scheduler names a concrete transport | B |
| AD-11 | `driver_has_no_wall_clock` [DEP][O-11] | `docs/06` §2; review focus `docs/07:133` | testscan over `secmp-transport/src`, `secmp-client-core/src` | `Instant::now`, `SystemTime::now`, `tokio::time::Instant::now` occur only in `secmp-client-core/src/clock.rs` | a timer reads time outside the injectable clock | B |
| AD-12 | `crypto_and_proto_stay_sans_io` [DEP][O-01] | `docs/02` §3 `:83` | `cargo metadata` normal closure of `secmp-crypto`, `secmp-proto` | contains none of `tokio`, `mio`, `socket2`, `futures-*`, `rustls*`, `arti-client`, `tor-*`; their `src` has no `async fn` | the sans-IO crates gain a runtime or I/O crate | B |

## (d) Scheduler — `secmp-client-core::scheduler` (§10, §9.1, §9.5; `docs/02` §4.4) — all Phase A, virtual clock

### d1 · LinkTask and modes

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| S-01 | `strict_one_link_per_queue` | §10.2 `:661` | Strict; 2 contacts (send s1, s2; recv r1, r2) + 2 pool queues | 6 links: 2 Send, 4 Recv; 6 distinct `IsolationKey`s | queues share a link | A |
| S-02 | `strict_send_link_one_send_per_period` | §10.2 `:660` | P = 10 000; 3 600 000 ms after `t_up` | 360 SEND frames at `t_up + k·10 000`, k = 1…360; inter-departure exactly 10 000 | a SEND is added, dropped or shifted | A |
| S-03 | `strict_recv_link_one_fetch_per_period` | §10.2 | P = 40 000; 1 h | 90 FETCH, each answered by 4 CELLR | FETCH count ≠ 90 or a response ≠ 4 frames | A |
| S-04 | `strict_counts_for_every_period` | §4.2 `PERIODS` | P ∈ {10, 20, 40, 80} s; 1 h | SEND counts 360, 180, 90, 45 | a period is mis-scaled | A |
| S-05 | `period_outside_set_rejected` | §9.8 `:643` `period_s ∈ PERIODS` | add route with `period_s` 0, 15, 81, 65 535 | `Error::BadPeriod`; no link created; `timing_draws` +0 | a non-PERIODS value schedules traffic | A |
| S-06 | `balanced_one_link_per_relay` | §10.2 `:662` | Balanced; 3 contacts on relay X, 1 on relay Y, pool 2 per relay | 2 links | Balanced opens per-queue links | A |
| S-07 | `balanced_slot_frames` | §10.2; §10.3 | Balanced, 1 slot | C2R: 1 (SEND or PING) then 1 FETCH_MULTI; R2C: 1 then 8; 11 frames | the slot shape varies | A |
| S-08 | `balanced_round_robin_due_rule` | §10.2 `:662` | send queues A (10 s), B (40 s), C (40 s), order A, B, C; slots at 10, 20, …, 100 s (k = 1…10) | SENDs to A, B, C, A, A, B, C, A, A, B | the RR pointer or the "≥ P_q ago" rule differs | A |
| S-09 | `balanced_ping_when_none_due` | §10.2 `:662` | single send queue A (20 s); slots k = 1…5 | SEND A, PING, SEND A, PING, SEND A | a non-due queue is sent to, or the slot is empty | A |
| S-10 | `balanced_fetch_multi_lists_all_recv_queues` | §10.2; D.2 `:823` | 3 contact recv queues + 2 pool | `count` = 5, fixed order (creation order), each entry its own committed ack; a 33rd queue → `Error::TooManyQueues` at add, no frame change | entries are omitted or the 32 limit is checked at tick time | A |
| S-11 | `balanced_rate_bound_integer_form` [O-17] | §10.2 `:662-663` | recv sets (P in s): 4×10; 5×10; 8×20; 16×40; 32×80; 4×10 + 1×80 | accept; `Error::RateBound`; accept; accept; accept; `Error::RateBound` | the bound is computed in floating point or off by one | A |
| S-12 | `lowbw_rate_bound_and_slot` | §10.2 `:663` | Low-bw: 5×40 accept, 6×40 reject, 10×80 accept, 11×80 reject; 1 h | as listed; 120 slots, 1 320 frames | T_LOWBW or its bound differs | A |
| S-13 | `direct_mode_implies_balanced` | §10.2 `:664` | direct on, mode Strict | effective mode Balanced; one link per relay; settings report `effective = Balanced` | direct mode keeps per-queue links | A |
| S-14 | `mode_change_tears_down_all_links` | `docs/02` §4.4 | Strict → Balanced at t | every old link: `TornDown(ModeChange)` at t, no unit after t; new link(s) start at t + U[0, 180 000] each, drawn independently | an old link keeps emitting or new links start together | A |
| S-15 | `link_phase_uniform_and_independent` | §10.6 (1) `:693` | 1 000 links, one trigger | each offset ∈ [0, 180 000]; KS p ≥ 0.01; 1 000 distinct draw indices | phases are shared, correlated or out of range | A |
| S-16 | `link_lifetime_uniform_6h_24h` | §4.2 `LINK_LIFETIME`; §10.6 (1) | 1 000 links | lifetime ∈ [21 600 000, 86 400 000]; KS p ≥ 0.01; the link's last unit < `t_up + L` | lifetime out of range or the link outlives it | A |
| S-17 | `lifetime_end_reconnects_fresh` [O-12] | §10.6 (1) | Strict send link P = 10 000, L forced to 21 600 000 (kat) | close at `t_up + L`; new link at `t_up + L + U[0, 180 000]` with a new `IsolationKey` and new phase; gap between the last old SEND and the first new SEND ≥ 10 000 | a handover sends twice within P_q or reuses the circuit | A |
| S-18 | `tick_anchor_after_hs2` [O-12] | §10.3 | `t_up` = 12 345 | ticks at 22 345, 32 345, …; nothing written at 12 345 | ticks drift with processing time or start at `t_up` | A |
| S-19 | `tick_writes_prebuilt_bytes_only` | §10.1 `:656`; CLAUDE.md §1.4 | 100 ticks, real and dummy cells | during each `tick()`: `seal_calls`, `tr_encrypt_calls`, `sign_calls`, `persist_calls` +0; bytes written = the prepared 4 352 | any preparation runs inside the tick | A |
| S-20 | `next_frame_prepared_before_tick` [O-13] | §10.1; §9.3 `:612` | 1 h Strict send + recv links | for every tick k + 1: `prepared_at < tick_time`; SEND prepared at tick k + 0; FETCH prepared at min(response k committed, tick k+1 − 1 000) | a frame is built at or after its tick | A |
| S-21 | `fetch_ack_uses_committed_state` | §9.3 `:612` | response k committed at tick k + 300; second run: response k arrives at tick k+1 − 500 | run 1: FETCH k+1 ack = highest id committed from response k; run 2: FETCH k+1 built at tick k+1 − 1 000 with the ack of response k − 1, duplicates of the re-fetch dropped by `cell_id` | FETCH is built before response k is processed, or waits past the lead | A |
| S-22 | `prepare_overrun_tears_down` [O-13] | §10.1 | `CellSource` blocks past tick k+1 | no unit at tick k+1; `TornDown(Overrun)`; reconnect at + U[0, 180 000]; `overruns` = 1 | a late frame is written off-schedule | A |
| S-23 | `in_flight_bound_two` | §10.3 `:678` | relay withholds responses | tick 1 → in-flight 1, tick 2 → 2, tick 3 → `TornDown(InFlight)` before any write; 0 bytes at tick 3; reconnect + U[0, 180 000] | a third request is written or the link waits | A |
| S-24 | `scheduler_reads_no_ui_state` | `docs/02` §4.4 "MUST NOT read UI/focus state" | type check + testscan of `scheduler/` | no parameter or field of a focus/visibility/typing type; identifiers `focus`, `visible`, `window`, `typing` absent | UI state can reach the scheduler | A |
| S-25 | `real_and_dummy_share_one_path` | §10.1; CLAUDE.md §1.4 | empty outbox; outbox with one text message | both cells 4 096 B via the same `tr::encrypt` call site (one site id in the counting accessor); content types 0x00 and 0x02; frames: same op, 4 352 B | dummies bypass the ratchet or take another code path | A |
| S-26 | `persist_before_send_order` | §7.5 `:488`; CLAUDE.md §1.7 | one slot; `Persist` fails in a second run | run 1 order: `tr_encrypt` < `persist` commit < `seal` < tick write; run 2: no frame prepared, `TornDown(Overrun)`, the message stays Queued | a cell is sealed before its state is durable | A |
| S-27 | `persist_before_ack_order` | §7.5; §9.3 `:612` | a received real cell; a commit failure | ack advances only after commit; on failure the next FETCH carries the old ack and the cell is re-fetched | an ack precedes the commit | A |
| S-28 | `every_delivered_cell_is_acknowledged` | §9.3 `:612` | a random 4 096-B cell between two real cells | discarded, decision committed, covered by the next ack; both real cells delivered | an undecryptable cell blocks the ack | A |
| S-29 | `refetch_dedup_by_cell_id` | §9.3 `:612` | the same CELLR delivered twice | processed once; delivered once | a duplicate is decrypted twice | A |
| S-30 | `send_response_handling` [O-24] | §10.3 `:672` | OK_SEND evicted Some(5) (real), Some(6) (dummy); ERR 3; ERR 4; ERR 7 | requeue msg of 5; forget 6; `route.mark_dead` and keep sending; `Alert(QueueAuth)` and keep sending; real cell requeued, `Alert(QueueRate)`; tick schedule unchanged in every case | an error changes the emission schedule | A |
| S-31 | `recv_noqueue_recreates_after_delay` [O-16] | §9.1 `:589`, `:593` | FETCH answered `present` 2 at t | identical QUEUE_NEW on a one-shot link at t + U[10 000, 300 000]; `committed_ack` = 0 and the dedup set cleared for that queue; the recv link keeps its ticks | re-creation is immediate, on the scheduled link, or keeps the old ack | A |
| S-32 | `sender_noqueue_discards_cell_id_map` | §9.1 `:593` | ERR 3 on send queue q with 7 mapped ids | q's `cell_id → outbox` map empty; a later `evicted` id for q is ignored | a stale id maps to a new message | A |

### d2 · ControlOps (§10.6 (2))

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| CO-01 | `control_ops_run_on_one_shot_links` | §10.6 (2) `:694` | QUEUE_NEW, QUEUE_DEL, LINK_PUT, LINK_GET (owner) | each on a new link with a new `IsolationKey`: handshake, one command (1 / 1 / 3 / 1 request frames), the response, close; never on a scheduled link | a control op rides a scheduled link or shares a circuit | A |
| CO-02 | `control_op_delay_uniform_1_to_60_min` [O-16] | §10.6 (2) | 1 000 ops enqueued at t, no related op | due ∈ [t + 60 000, t + 3 600 000]; KS p ≥ 0.01 | the delay is fixed, out of range or biased | A |
| CO-03 | `control_op_delay_from_related_op` [O-16] | §10.6 (2) "from any related operation" | LINK_PUT executed at t1; a related QUEUE_DEL (same invitation) enqueued at t1 − 10 000 | due ≥ t1 + 60 000 | related ops run within a minute of each other | A |
| CO-04 | `prompt_ops_are_not_delayed` | §10.6 (2) | invitee LINK_GET consume; inviter LINK_PUT | started at t (delay 0) on one-shot links | a waiting user is delayed | A |
| CO-05 | `owner_status_reissues_identical_put` | §9.7 (1) `:630` | owner status answers {0, 0} before `expires` | identical LINK_PUT (`ld_id`, `one_time`, `expires_bucket`, `owner_pk`, blob byte-equal; new `sess_id`, `cmd_seq`, token) on a one-shot link after U[60 000, 3 600 000] | the re-issue differs or reuses a link | A |
| CO-06 | `control_op_retried_after_link_failure` [O-14] | §10.6 (1) | the one-shot link closes before RELAYINFO twice | retried with the LR-04 back-off; executed exactly once after success | a failed op is dropped or runs twice | A |
| CO-07 | `control_ops_leave_scheduled_traces_unchanged` | §10.1, §10.6 | same seed with and without 5 control ops | the scheduled links' traces are equal; the only extra units belong to one-shot links | a control op shifts a scheduled tick | A |
| CO-08 | `control_op_draws_from_timing_rng` | §10.1 | control op enqueue | `timing_draws` +1 per op; content draws unaffected | a delay comes from the content stream | A |

### d3 · QueuePool (§10.6 (3))

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| QP-01 | `pool_keeps_two_spares_per_relay` | §10.6 (3) `:695` | start with 0 spares; hand one out later | two QUEUE_NEW control ops (CO-02 delays); after the hand-out one replacement; never < 2 after replenishment, per relay | the pool is not refilled or refilled synchronously | A |
| QP-02 | `pool_queue_fetched_at_pool_period` [O-17] | §10.6 (3) | Strict, 1 spare queue | its own recv link, FETCH every 80 000 | pool queues are not fetched or use another period | A |
| QP-03 | `pool_handout_needs_no_queue_new` | §10.6 (3) | create and accept an invitation | QUEUE_NEW count at the hand-out instant 0; the replacement starts ≥ 60 000 later | an invitation triggers an immediate QUEUE_NEW | A |
| QP-04 | `pool_queue_never_idles_out` | §10.6 (3); §4.2 `QUEUE_IDLE_TTL` | 31 days virtual with the M5 relay sweeper | no pool queue answers `present` 2 | a pool queue expires | A |
| QP-05 | `pool_handout_recreates_link_with_announced_period` [O-17] | §10.6 (1), (3) | hand out a pool queue announced with P = 10 s | its 80-s recv link closes; a new recv link (new key, phase U[0, 180 000]) fetches every 10 000 | the period changes in place on the old link | A |

### d4 · Outbox (§9.5, §10.4; in-memory behind a trait)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| OB-01 | `outbox_states` [O-18] | §10.4 `:682` | enqueue; OK_SEND id 9; Receipt{delivered} | Queued → Relayed(9) → Delivered | a state transition is missing | A |
| OB-02 | `outbox_requeues_evicted_real_with_new_key` | §9.5 `:622` | real cell id 9 evicted | re-sent at the next slot of that queue: new cell bytes, new TR position, same `msg_id`; an evicted dummy id is forgotten | an evicted real cell is re-sent byte-identical or a dummy is re-sent | A |
| OB-03 | `outbox_failed_after_30_days` | §10.4 `:682` | never relayed | Queued at 2 591 999 000 ms; Failed at 2 592 000 000 ms | the 30-day rule is off by a unit | A |
| OB-04 | `outbox_resends_unreceipted_after_restart` [O-18] | §10.4 `:683` | 3 Relayed (1 Delivered) when ERR 3 starts | the 2 unreceipted are re-sent (new cells) after the re-creation; the Delivered one is not | lost real messages are not re-sent | A |
| OB-05 | `outbox_fragments_large_message` | §7.6 `:501` | one text AppMessage, payload 65 535 B | Batch body 1 + 23 + 65 535 = 65 559 B; fragments ⌈(1 + 65 559)/1 669⌉ = 40; 40 consecutive SENDs of that queue carry them; tick times equal to the idle run | fragmentation adds frames or shifts ticks | A |
| OB-06 | `receipts_ride_normal_slots` [O-18] | §10.4 `:682` | 3 delivered messages from a verified contact | one Receipt{delivered, count 3} cell in a normal slot; no extra unit | a receipt is sent out of slot | A |
| OB-07 | `outbox_is_the_store_boundary` [O-18] | `docs/07:122` | manifest + type check | scheduler uses only the `Outbox` and `Persist` traits; `secmp-client-core` has no `secmp-store` dependency in M6 | M6 pulls the M7 store forward | A |
| OB-08 | `receiver_dedups_by_msg_id` | §10.6 (4) `:696`; §9.5 | a message re-sent after eviction arrives twice | delivered to the application once | a re-sent message is shown twice | A |

### d5 · Rotation, reconnect, back-off (§8.4, §10.6 (1); M05-review F-1 M6 part)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| LR-01 | `new_link_required_rotates` | §4.2 `LINK_MAX_FRAMES`; OPEN-M5-03 | c2r counter set to 2^20 − 1 (kat) | `TornDown(NewLinkRequired)`; reconnect at + U[0, 180 000] with a new key | the link seals past the bound | A |
| LR-02 | `reconnect_jitter_after_failure` | §10.6 (1) "reconnect" trigger | stream closed at t | next attempt at t + U[0, 180 000]; KS p ≥ 0.01 over 1 000 | reconnects are immediate or synchronised | A |
| LR-03 | `backoff_closed_before_relayinfo` [O-14] | F-1 (M6); §9.7 (7) | consecutive `ClosedBeforeRelayInfo`, n = 1…8 | delay_n ∈ [0, min(180 000 · 2^(n−1), 3 600 000)]: caps 180 000, 360 000, 720 000, 1 440 000, 2 880 000, 3 600 000, 3 600 000, 3 600 000; n resets to 1 after an HS2 | the client hammers the HELLO bucket or never resets | A |
| LR-04 | `backoff_uses_timing_rng_only` | §10.1 | back-off with outbox empty vs full | identical delays for the same seed | activity changes a reconnect time | A |
| LR-05 | `reconnect_never_changes_transport` | CLAUDE.md §1.5 | Tor-mode link fails 8 times | every attempt via the Tor provider | repeated failure falls back to direct | A |
| LR-06 | `rotation_and_reconnect_keep_send_spacing` | §10.2 "at most once per P_q" | 100 rotations/reconnects of a P = 10 000 send link | every pair of consecutive SENDs of the queue ≥ 10 000 apart | a handover doubles a SEND | A |

## (e) `secmp-testkit` binary `two-clients` (`docs/07:123`)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| TC-01 | `two_clients_cli_contract` | `docs/07:123` | `two-clients --help`; bad flag | flags `--role {inviter,invitee,both}`, `--mode {strict,balanced,lowbw}`, `--transport {mem,loopback,tls,tor}`, `--relay-ref`, `--invite-out`, `--invite-in`, `--script`, `--duration-s`, `--trace-out`, `--tor-dir`; exit 2 on usage error; exit 3 when the chosen transport is unavailable (never another transport) | a flag is missing or a transport is substituted | C |
| TC-02 | `two_clients_profiles_are_in_memory` | `docs/07:123` | `--role both --transport mem`, 600 s virtual | no file created except `--trace-out` (directory listing before/after) | profile state touches disk (M7) | C |
| TC-03 | `two_clients_scripted_invitation_handshake` | §5.5, §6.4–6.6 | `--role both --transport mem` | LINK_PUT + pool queue; LINK_GET consume; HX initiator 3 cells; responder accept; both report `session=up`; the 60-digit SAS strings equal | the M3–M5 path breaks under the scheduler | C |
| TC-04 | `two_clients_exchange_script_mem` | §7.6 | script: 100 messages each way, sizes seeded 1…65 535 B | each delivered once, `seq` order, bytes equal | a message is lost, duplicated or altered | C |
| TC-05 | `two_clients_loopback_tcp` | `docs/06:95` | relay binary on 127.0.0.1, Strict and Balanced, 20 messages each way | all delivered; trace: after HS2 every unit 4 352 B | the TCP path differs from mem | C |
| TC-06 | `two_clients_direct_tls_loopback` [DEP] | §8.1 | relay direct listener, pinned SPKI, 20 messages each way | all delivered | direct TLS does not carry a conversation | C |
| TC-07 | ⚙ `two_clients_two_machines_real_tor` [DEP] | `docs/07:131` | owner: inviter on machine 1, invitee on machine 2, test relay (C tor); Strict P = 10 s; 50 messages each way | all 100 delivered within 30 min; traces + latency file under `docs/measurements/M6-evidence/` with machine names, dates, commit | the acceptance over real Tor fails | C |
| TC-08 | ⚙ `two_clients_two_machines_direct_tls` [DEP] | `docs/07:131` | as TC-07 over the test relay's direct listener | all 100 delivered; evidence as TC-07 | the acceptance over direct TLS fails | C |
| TC-09 | `two_clients_trace_schema` | (g), (h) | `--trace-out` | JSON lines with exactly the keys `t_ms`, `len`, `dir`, `link_slot` (units) or `event`, `msg`, `t_ms` (message events); no id, key or address field | the trace leaks identifiers or cannot feed AI/MR | C |

## (f) `turmoil` simulations (`docs/07:124`; `docs/06` §4 "asserts eventual delivery and no key reuse")

Every SIM row: two clients and one relay host (the M5 relay's sans-IO connection driven by a testkit host task),
`TurmoilProvider`, Strict unless stated, P = 10 s, seeded; common assertions **(E)** every real message enqueued is
delivered to the application exactly once, and **(K)** the digests of all message keys used by each sender are pairwise
distinct (H-12 method).

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| SIM-01 | `sim_loss_breaks_links_eventual_delivery` [DEP] | `docs/07:124` | `fail_rate(0.01)`, `repair_rate(0.5)` (turmoil breaks TCP on loss), 200 messages each way, 2 h | (E), (K); every reconnect delay within LR-02/LR-03 bounds | loss strands a message or reuses a key | C |
| SIM-02 | `sim_partition_heals` [DEP] | `docs/07:124` | partition A ↔ relay 30 min | (E), (K); the relay's reported evicted ids for B → A equal the ids the test predicts from the trace (cells beyond 128 unfetched) | evictions are mis-reported or a real message is lost | C |
| SIM-03 | `sim_relay_restart_recovery` [DEP] | §9.1, §10.4 `:683` | `bounce(relay)` at 1 h | recipients re-create identical queues at U[10 s, 300 s]; senders keep sending; (E) incl. messages lost in the restart; (K); no new invitation | recovery needs an invitation or loses messages | C |
| SIM-04 | `sim_both_clients_restart` [DEP][O-18] | `docs/07:124` | both clients crash at 1 h, restart from `MemPersist` snapshots | sessions continue; (E); (K) | a restart reuses a key or drops the outbox | C |
| SIM-05 | `sim_crash_between_persist_and_write` [DEP] | §7.5 `:488` | crash after persist, before the tick write | the persisted-but-unsent position is skipped; the next cell uses the next position; (K) | a key is reused after the crash | C |
| SIM-06 | `sim_latency_does_not_move_emission` [DEP] | §10.1 | message latency 10…2 000 ms vs 0 | C2R emission times identical (RTT < P, no in-flight teardown) | emission waits for responses | C |
| SIM-07 | `sim_slow_link_in_flight_teardown` [DEP] | §10.3 `:678` | one-way latency 25 s, P = 10 s | `TornDown(InFlight)` at the third tick; reconnect per LR-02 | a slow link accumulates requests | C |
| SIM-08 | `sim_replay_deterministic` [DEP] | `docs/06` §4 | SIM-03 twice, same seeds | byte-identical traces | a source of nondeterminism exists | C |
| SIM-09 | `sim_hello_flood_backoff_recovery` [DEP][O-14] | F-1 (M6) | an attacker host sends HELLO at 8/s for 600 s (relay bucket 16, 4/s) | honest links back off per LR-03; every link is up by flood end + 3 600 s + 60 s | clients never recover or retry without back-off | C |
| SIM-10 | `sim_balanced_relay_restart` [DEP] | §10.2 | SIM-03 in Balanced | (E), (K); FETCH_MULTI entries `present` 2 until re-creation | Balanced recovery differs | C |

## (g) Activity independence (`docs/07:125`; §10.1; CLAUDE.md §1.4; `docs/06` §4 Property)

Activity trace generator (seeded, CI seed per X-07 of M5): user sends at a random Poisson rate in [0, 1]/s with sizes
1…65 535 B, bursts of 100, peer messages arriving, receipts, UI focus toggles (fed to the core API, never to the
scheduler), all over 6 h virtual; "idle" = the same `TimingRng` seed with no activity.

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| AI-01 | `activity_independence_strict_virtual` | `docs/07:125` | 64 activity traces, 2 contacts + pool, `VirtualDriver` | C2R trace equal to idle: same length, same `len` and `dir` per position, max \|Δt\| ≤ 5 ms (report the max; expected 0) | any frame's time, size or count depends on activity | A |
| AI-02 | `activity_independence_balanced_virtual` | as AI-01 | Balanced, 4 contacts | as AI-01 | as AI-01 | A |
| AI-03 | `activity_independence_lowbw_virtual` | as AI-01 | Low-bw, 5 contacts at 40 s | as AI-01 | as AI-01 | A |
| AI-04 | `activity_independence_when_receiving` | §10.1 | local idle, peer active | local C2R trace equal to both-idle | receiving shifts our emission | A |
| AI-05 | `timing_draws_independent_of_activity` | §10.1 | AI-01 runs | `timing_draws` sequence equal between idle and active | activity consumes timing randomness | A |
| AI-06 | `activity_independence_both_directions` | §10.1; D.2 | AI-01 with the deterministic relay | R2C trace: same length and sizes; times within 5 ms | responses reveal activity | A |
| AI-07 | `ks_one_hour_idle_vs_active` [DEP][O-21] (⚙ Tor part) | `docs/07:125` "real hardware" | dispatch job `ks-hour`: loopback TLS relay, Strict P = 10 s, 2 contacts; 1 h idle then 1 h active (1 message / 30 s mean, 10 bursts of 20); ⚙ the same over real Tor | two-sample KS on per-link C2R inter-departure times (handshakes excluded): p ≥ 0.01 per link and pooled; all units 4 352 B; D, p, n committed | the real-time path leaks activity | C |
| AI-08 | `control_ops_are_the_only_extra_units` | §10.6 (2); §11.3 (3) | activity incl. invitation create/accept | active − idle = units of one-shot links only | activity changes a scheduled link | A |
| AI-09 | `tick_path_reads_no_outbox` | review focus `docs/07:133` | testscan over `scheduler/` | the `tick` function bodies contain no `Outbox`/`outbox`/`CellSource` identifier; outbox state is read only inside `prepare` | an activity conditional enters the tick path | A |
| AI-10 | `ks_tool_detects_planted_dependence` [O-21] | (control) | the AI-07 analyser on a synthetic trace whose gaps shrink by 1 ms while "active" | p < 0.01 | the KS tool cannot detect a 1-ms shift at that n | C |

## (h) Measurement report `docs/measurements/M6-traffic.md` (`docs/07:126`; ADR-018)

| # | Test | Spec | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| MR-01 | `bandwidth_model_matches_capture` | §10.2 `:666` | 24 h virtual per mode (Strict 1 contact P = 10 s + 2 pool at 80 s; Balanced 4 contacts; Low-bw 5 contacts at 40 s) | per link: units = Σ over its up-intervals (⌊(t_down − t_up)/P⌋ per tick kind × frames per slot); bytes = units × 4 352 + 5 765 per handshake; per-contact Strict steady state 7 × 4 352 B / 10 s = 3 046.4 B/s = 263 208 960 B/day; Balanced 11 × 4 352 / 10 s = 413 614 080 B/day; Low-bw 11 × 4 352 / 30 s = 137 871 360 B/day | the capture and the model disagree | A |
| MR-02 | `drain_after_offline_virtual` | §9.5; `docs/07:126` | Strict P = 10 s, recipient offline 1 h and 24 h (lifetimes forced ≥ window, kat) | relay evicts exactly 232 (1 h) and 8 512 (24 h) cells; after return the queue is empty within 45 recv ticks; every real message sent before or during the window delivered by then; Balanced 4 contacts: empty within 130 slots; Low-bw 5×40 s: within 153 slots; exact tick counts recorded | drain is slower than the F/F_M arithmetic or a real message is lost | A |
| MR-03 | `m6_traffic_report_sections` | `docs/07:126` | xtask doc check of the report | headings: Method, Bandwidth (model + measured, B/s and MB/day, with/without Tor), Tor overhead, Latency over Tor, CPU, Drain 1 h/24 h, Recommendation (ADR-018), Gaps; every ⚙ number is present or reads "not measured — <reason, date>" | a section is missing or a ⚙ value is invented | C |
| MR-04 | ⚙ `tor_overhead_and_latency_measured` | §10.2 "Tor adds ≈ 7 %" | owner host: Strict P = 10 s and Balanced 4 contacts over real Tor, ≥ 100 messages each way | report: bytes on the wire per 4 352-B frame (model 9 cells × 514 B = 4 626 B, +6.3 %), latency median/p95/max; plausibility p95 ≤ 2P + 20 s = 40 s (Strict) | Tor overhead or latency are not measured | C |
| MR-05 | `cpu_per_slot_measured` (VM part ⚙) | `docs/07:126` | `criterion`-free timer in testkit: prepare per slot (TR encrypt + persist + seal), 10 000 slots; process CPU % over 1 h per mode on the dev host and ⚙ the Windows VM | median and p99 µs per prepare; p99 < 3 000 µs (M3 bound); CPU % per mode | CPU is not reported or exceeds the M3 bound | C |
| MR-06 | `recommendation_names_every_parameter` [O-22] | ADR-018 | report §Recommendation | one row each for `PERIODS`, `T_BALANCED`, `T_LOWBW`, `F`, `F_M`, `P_POOL`, with measured cost and the §10.1 check; ADR-018 stays "Proposed (owner decides after M6)" | a parameter is omitted or ADR-018 is self-accepted | C |
| MR-07 | `bootstrap_cost_measured` [O-03] | ADR-051 (compression off) | ⚙ or dispatch `tor-smoke`: bytes downloaded and seconds for a cold Arti bootstrap without compression | both numbers in the report | the cost of dropping `compression` is unknown | C |

## (i) F-M6 follow-ups (M05-review §C/§H, VD-M5-FIX)

| # | Test | Source | Input | Expected (exact) | Would fail if | Ph |
|---|---|---|---|---|---|---|
| G-01 | `ok_send_with_implausible_evicted_id_is_rejected` | F-4, R-122 | OK_SEND `cell_id` 10 with (present, id) = (1, 0), (1, 10), (1, 11), (0, 3); (1, 1), (1, 9), (0, 0) | first four `Rejected`, link closed; last three accepted (`None` for (0, 0)); decoder unchanged | the client accepts an id outside 1…cell_id − 1 | A |
| G-02 | `caps_have_no_partial_eq` | F-5, R-123 | `compile_fail,E0369` doctest `RecvCap == RecvCap` and for `SendCap`; `ct_eq` | doctests fail to compile with E0369; `ct_eq` = 1 / 0 for equal / one-byte-different seeds; the 6 test sites use `ct_eq` | `PartialEq` returns on seed-bearing types | A |
| G-03 | `ct_guard_sites_use_ct_eq` | F-6, R-124 | testscan rule over proto `link/relay.rs` (mac1), `link/client.rs` (mac2), `link/ids.rs` (token), crypto `mac.rs` (verify); fixture with `==` at one site | each site calls `ct_eq`/`hmac_sha256_verify`, no `==`/`!=` on those values; the fixture is refused naming the site; TEST-SPEC-M5 (g) gains the sentence "CT-01…04 are floor-only; G-03 pins the comparison primitive" | a reintroduced `==` passes the gate | A |
| G-04 | `normal_dependencies_match_adr_allowlist` | F-7, R-126 | `cargo metadata`; per-crate allowlist in `expect` (`secmp-relay`, `secmp-transport`, `secmp-client-core`, `secmp-testkit` normal deps); fixture manifest with an unlisted crate | gate refuses the fixture naming crate and package; in Phase A every allowlist is workspace-only; Phase B widens it exactly to ADR-051 | a direct dependency enters without its ADR line | A |
| G-05 | `fuzz_executor_depth` | F-8, R-127 | `expect`; smoke and nightly commands | FZ-07/FZ-08 (M5) run with `-len_control=0` and their `FUZZ_MAX_LEN`; nightly share 3 600 s each; evidence lists runs and `lim` per target with `lim` = max_len | the executor fuzzers stay shallow | A |
| G-06 | `testkit_manifest_and_workflow_texts` | F-10, R-131, R-132, R-133 | `crates/secmp-testkit/Cargo.toml`; `ci-dispatch.yml`; `fuzz-nightly.yml` | comment names feature `harness` and the normal `serde_json`; `secmp-relay`, `secmp-transport` (and `secmp-client-core`) via `[workspace.dependencies]`; dispatch input lists `proverif-link`; the nightly comment's target count × seconds equals `FUZZ_TARGETS.len()` × `FUZZ_NIGHTLY_SECONDS`/share (policy check) | a stale text survives | A |
| G-07 | `v16_checks_unpad` and `h01_identical_queue_new_answers_ok` | F-11, R-134, R-135 | V-16; `scenarios.rs:369` | V-16 asserts `unpad(opened)` Ok and length ≤ 4 335 (no re-pad); the comment is replaced by an identical QUEUE_NEW answered OK_QUEUE_NEW with the same ids | the tautology or the empty comment remains | A |
| G-08 | `mutants_report_has_unviable_breakdown` | F-15, R-148 | mutants gate output | per package: unviable count by file (top 5) and by mutation operator; informative, no threshold | the crypto unviable share stays unexplained | A |
| G-09 | `relay_info_without_placeholder_signature` | R-144 | one HELLO | `sign_calls` = 1 per RELAYINFO; RELAYINFO bytes = V-01's | the placeholder signature remains | A |
| G-10 | `no_ignore_without_adr` | R-155 | testscan; fixture with `#[ignore]` | refused naming the file unless listed in `expect::IGNORE_ADR` (empty) | an `#[ignore]` slips in | A |
| G-11 | `harness_cap_setters_take_effect` | VD-M5-FIX (convo.rs `set_send_cap`/`set_recv_cap` mutants survived) | H-12 after re-creation: replace caps via the setters | the next SEND uses the new `sid` and the next FETCH the new `rid` (relay-side capture); a no-op setter fails the test; one-off `cargo mutants -p secmp-testkit --features harness -f '**/convo.rs'` evidence: 0 missed | the setters stay untested | A |
| G-12 | `relay_idle_and_age_bounds_from_schedule` [O-15] | M05 C-3 "M6 adjusts" | relay config defaults; SIM-01…SIM-10 | `link_idle_secs` = 240 (= 3 × 80 s); linked age limit 87 000 s (= 86 400 + 600); 0 relay idle/age closes in every SIM run | a compliant client is cut by the relay | B |

## (j) Gates

### Kani (`KANI_PACKAGES` += `secmp-client-core`)

| # | Harness | Property | Ph |
|---|---|---|---|
| K-01 | `kani_balanced_rr_selects_due_or_ping` | ≤ 4 queues, P ∈ PERIODS, arbitrary `last_send ≤ now`: the chosen queue is the first due one from the RR pointer, `now − last ≥ P`; none due ⇒ PING | A |
| K-02 | `kani_in_flight_bound` | event sequences ≤ 8 (tick, response, close): in-flight ∈ {0, 1, 2}; a tick at 2 ⇒ `TornDown(InFlight)`, no write | A |
| K-03 | `kani_tick_time_checked` | `t_up + k·P` with `checked_*`; overflow ⇒ error, never wrap (u64 ms, k < 2^32, P ≤ 80 000) | A |
| K-04 | `kani_uniform_draw_in_range` | one rejection-sampling round: accepted value ∈ [a, b] for every a ≤ b < 2^32; rejection probability < 1/2 | A |
| K-05 | `kani_backoff_cap` | cap(n) = min(180 000 · 2^(n−1), 3 600 000) has no overflow for n ∈ [1, 2^32) and is monotone | A |
| K-06 | `kani_rate_bound_integer_form` | for ≤ 32 queues with P ∈ PERIODS: Σ 80 000/P ≤ 32 ⇔ Σ 1/P ≤ 0.4 (exact rational comparison in the harness) | A |
| K-07 | `kani_evicted_range` | G-01's rule: accepted iff (0, 0) or (1, id) with 1 ≤ id < cell_id | A |

Negative control: one committed K-02 run with the in-flight check removed, `VERIFICATION:- FAILED`; every `cover!` SATISFIED.

### Property tests (default seed + CI-run seed)

| # | Name | Invariant | Ph |
|---|---|---|---|
| P-01 | `prop_schedule_independent_of_activity` | `docs/06` §4 model-based test: random mode, periods, link set, activity ⇒ C2R trace equal to idle (Δt ≤ 5 ms) | A |
| P-02 | `prop_at_most_once_per_period` | any mode, any rotation/reconnect sequence ⇒ consecutive SENDs to a queue ≥ P_q apart | A |
| P-03 | `prop_outbox_matches_model` | random enqueue/OK_SEND/evict/NOQUEUE/receipt/30-day sequences ⇒ same states as a plain model | A |
| P-04 | `prop_draws_in_range` | phases, lifetimes, control delays, re-creation delays, back-off all inside their intervals | A |
| P-05 | `prop_pipelined_matching_any_chunking` [DEP] | random chunking and response delays (order kept) over `AsyncSession` ⇒ every response matched to its request | B |
| P-06 | `prop_control_ops_isolated_and_delayed` | random op sets ⇒ one new key per op; non-prompt ops respect CO-02/CO-03 | A |
| P-07 | `prop_no_message_key_reuse_across_crashes` | random crash points around persist/seal/write ⇒ message-key digests pairwise distinct | A |

### Fuzz targets (2 min per PR, ≥ 1 committed seed each; `FUZZ_TARGETS` += 4)

| # | Target | Input → invariant | Ph |
|---|---|---|---|
| FZ-01 | `client_pipeline_responses` | structured: outstanding request kinds + arbitrary opened plaintexts ⇒ no panic; Ok only for D.2-fitting answers; any misfit ⇒ `Rejected` | A |
| FZ-02 | `tls_pin_verifier` [DEP] | arbitrary end-entity DER + intermediates ⇒ never panics; Ok only for a single cert whose SPKI hash equals the pin (harness pins the hash of the input when parseable) | B |
| FZ-03 | `relayref_onion_to_hsid` [DEP] | arbitrary 35 B ⇒ total; Ok iff version 0x03 and checksum valid; Arti's parse re-encodes to the input | B |
| FZ-04 | `scheduler_event_sequence` | arbitrary events (tick, response, close, add/remove queue, mode change, clock jump ≤ 24 h) ⇒ no panic; in-flight ≤ 2; ≤ 1 SEND per P_q per queue; every unit 4 352 B | A |

Not fuzzed by us (library-owned, upstream fuzzing): rustls record and handshake parsing (rustls fuzzers, OSS-Fuzz), Arti
cell, directory and consensus parsing (Arti's own fuzz targets), tokio. The M5 targets are unchanged except G-05.

### Mutants, ct, ProVerif, coverage, xtask

| # | Test | Expected | Ph |
|---|---|---|---|
| MU-01 | `mutants_scope_includes_client_core_and_transport` [O-23] | `MUTANT_PACKAGES` = crypto, proto, relay, client-core, transport; `MUTANT_EXCLUDE_FILES` gains only the Arti glue file(s) that need a live network, each named in ADR-047 Amendment 4 (text in ADR-051 §Consequences); per-package rule of Am. 2; per-shard time reported; `secmp-testkit` stays outside (G-11 instead) | B |
| CT-00 | `ct_targets_unchanged_in_m6` | `expect::CT_TARGETS` equals the M5 list. No new secret-dependent comparison: scheduler and outbox handle public ids (`cell_id`, queue refs) only; the SPKI pin is public (it is in the invitation); caps equality (G-02) is `subtle`-based and test-only; dummy vs real preparation time is off the tick path (S-19, AI-*) | C |
| PV-01 | `proverif_models_unchanged_in_m6` | `PROVERIF_MODEL_SHA256` unchanged; `proverif-hx`, `proverif-link` green. No new model: the §11.1 Scheduler row (activity independence, lifecycle correlation) is a timing property outside ProVerif's symbolic model; it is evidenced by P-01, AI-01…AI-08, K-01…K-06 | C |
| COV-01 | `coverage_strict_includes_client_core` [O-23] | `COVERAGE_STRICT` = crypto, proto, client-core (≥ 90 % lines) | B |
| COV-02 | `coverage_transport_80_with_tor_glue` [O-23] | `secmp-transport` ≥ 80 % lines with the Arti glue counted; an exclusion list exists only with the reviewer's written approval | B |
| X-01 | `cooldown_covers_m6_lock` [DEP] | every `Cargo.lock` crate published ≥ 7 days before the commit; the youngest crate and its date in the report (the unconstrained resolve of 2026-10-09 had 23 crates < 7 days: `cargo update --precise` them back) | B |
| X-02 | `deny_duplicate_skips_are_justified` [DEP][O-04] | `deny.toml` `skip` lists each duplicated crate with version, the direct dependency that pulls it and a reason; no `skip-tree`; `cargo deny check bans` green | B |
| X-03 | `vet_records_for_m6_closure` [DEP][O-02] | direct deps covered per ADR-051 (import, trust or owner delta audit); transitive gaps are tracked exemptions naming the direct dep; `check_vet_closure` (zero-exemption closure of crypto/proto) unchanged | B |
| X-04 | `licenses_cover_m6_closure` [DEP][O-05] | `cargo deny check licenses` green with only the ADR-051-approved additions | B |
| X-05 | `kani_and_fuzz_lists_m6` | `KANI_PACKAGES` += client-core, `KANI_HARNESSES` += K-01…K-07, `FUZZ_TARGETS` += FZ-01…FZ-04, `FUZZ_MAX_LEN` entries for each | A |
| X-06 | `windows_builds_nasm_from_source` [DEP][O-06] | `windows-native` and `xwin-cross` set `AWS_LC_SYS_PREBUILT_NASM=0` and install NASM; the build log shows no prebuilt NASM object | B |
| X-07 | `optional_jobs_are_not_required` [O-20][O-21] | `tor-smoke` and `ks-hour` exist only in `ci-dispatch.yml` with distinct names; `REQUIRED_JOBS` unchanged; no required job opens a non-loopback socket | C |
| X-08 | `two_clients_not_shipped` | `two-clients` is a `secmp-testkit` bin with `required-features = ["harness"]`; `BINARIES` unchanged; not in the release SBOM | C |
| X-09 | `scheduler_core_has_no_tokio` [O-11] | testscan: no `tokio` path in `secmp-client-core/src/scheduler/core/**`; the tokio driver lives in `scheduler/run.rs` | A |
| X-10 | ⚙ `win_test_runs_transport_suites` [DEP] | `cargo xtask win-test` runs the TLS rows, AD-07/AD-08 and TOR-10 on the VM; log committed | B |

## (k) Maps

**Acceptance (`docs/07:131`).** Two instances on two machines over real Tor ⚙ TC-07 (substitute path: TC-05, `tor-smoke`) ·
over direct TLS ⚙ TC-08 (TC-06) · activity-independence AI-01…AI-06, P-01 (virtual), AI-07 (real; ⚙ Tor part) ·
simulations SIM-01…SIM-10 · ⚙ Arti bootstraps in the Windows VM TOR-10 · transport KATs pass in the VM X-10 (TLS-*,
AD-07/AD-08, M5 link vectors).

**Deliverables (`docs/07:121-126`).** tor TOR-01…TOR-10 · tls TLS-01…TLS-15 · scheduler S-*, CO-*, QP-*, OB-*, LR-* ·
`two-clients` TC-* · turmoil SIM-* · activity independence AI-* · report MR-*.

**Review focus (`docs/07:133`).** activity on the tick path AI-09, S-19, S-24, AD-11 (`Instant::now` grep) · outbox
conditionals outside `prepare` AI-09 · isolation per link TOR-02, CO-01, S-01 · exactly one TLS KX group TLS-01, TLS-03,
TLS-10, TLS-12 · Tor never bypassed TOR-05, TOR-06, LR-05.

**Invariants.** §1.3 hybrid-only TLS-01, TLS-03, TLS-14 · §1.4 constant rate S-19…S-25, AI-* · §1.5 fail closed TOR-03,
TOR-05, AD-04 · §1.6 G-02, G-03 · §1.7 S-26, S-27, SIM-05 · §1.9 G-04, X-01…X-04.

**F-M6 (M05-review §H).** F-1 (M6 part) AD-06, LR-03, SIM-09 · F-4 G-01, K-07 · F-5 G-02 · F-6 G-03 · F-7 G-04 · F-8 G-05 ·
F-10 G-06 · F-11 G-07 · F-15 G-08 · R-144 G-09 · R-155 G-10 · convo.rs mutants G-11 · C-3 adjustment G-12.
