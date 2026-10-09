### ADR-051 — Async driver and transport providers in M6: tokio runtime scope, Arti/rustls dependency set, sans-IO boundary

**Status.** Proposed (planner, 2026-10-09; M6 planning). Two classes in one record: **Part 1 (runtime scope, sans-IO
boundary, API shape) — engineering**, accepted by the reviewer under the owner delegation of 2026-09-30; **Part 2
(shipped dependency set, `cargo vet` trust/audits, license and build-input decisions) — OWNER class**: it takes effect
only with the owner's written approval and the owner's own `cargo vet` records (an agent never records itself,
`docs/06` §3). Phase B of M6 lands no dependency before both. Supersedes nothing; extends ADR-049 and ADR-050 (3).

**Context.** `docs/07` §M6 delivers `secmp-transport::tor` (Arti 2.6.x / `arti-client` 0.46.x, `onion-service-client`,
`rustls`, per-link isolation, bootstrap events, state dir) and `::tls` (rustls/aws-lc-rs, `X25519MLKEM768` only, SPKI
pin, no tickets/0-RTT), the constant-rate scheduler, `turmoil` simulations and an acceptance over real Tor and direct
TLS. M5 kept every shipped crate free of third-party runtime code (ADR-049: relay std-only; ADR-050: synchronous
`secmp-transport` over `std::io`, "the asynchronous driver … needs its own ADR"). Arti is async-only; turmoil
simulates tokio's network; the relay's direct listener (`docs/05` §7, `docs/02` §2) needs a TLS server. A probe resolve
on 2026-10-09 (scratch crate: the pins below plus the workspace crypto pins, crates.io index) gives ≈ 398 normal
crates for `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, 412 for `x86_64-pc-windows-msvc`, ≈ 477 incl. build
dependencies on all targets, ≈ 360 of them new to `Cargo.lock`; 34 crate names in two or three versions (Arti brings
`x25519-dalek` 2, `ed25519-dalek` 2, `curve25519-dalek` 4, `sha2` 0.10, `rand` 0.8 beside the workspace's newer
majors); ≈ 45 build scripts including two C builds (`aws-lc-sys`, `libsqlite3-sys` bundled); licenses outside the
`deny.toml` allowlist: `Unlicense` (`async_executors`), `CC0-1.0` (`notify`), and `priority-queue` "LGPL-3.0-or-later
OR MPL-2.0"; by crate name 281 of ≈ 360 new crates have some audit in the five imported sets, 79 none (version coverage
to be established by `cargo vet suggest`); the imported audits end at `arti-client` 0.35, `tokio` 1.42.1,
`tokio-rustls` 0.24.0 and cover `rustls` up to 0.23.45. In an unconstrained resolve 23 crates were younger than 7 days
(youngest: `tokio-util` 0.7.20, published 2026-10-09); the lock must be pinned back (`cargo update --precise`).

**Decision — Part 1 (engineering).**
1. *Runtime.* `tokio` is the one async runtime (OPEN-M6-01 A). Users: `secmp-transport` (`driver`: `AsyncSession`,
   `AsyncRelayQueueTransport`, `StreamProvider`; providers `tor`, `tls`), `secmp-client-core::scheduler::run` (the
   driver of the sans-IO scheduler core), `secmp-testkit` (`MemProvider`, `TurmoilProvider`, the turmoil relay host,
   `two-clients`). Normal features: `rt`, `rt-multi-thread`, `net`, `time`, `sync`, `io-util`; `macros`, `fs`,
   `process`, `signal` are not requested by our crates.
2. *Sans-IO boundary.* `secmp-crypto` and `secmp-proto` keep no runtime and no I/O crate in their normal closure and no
   `async fn` (test AD-12); `secmp-relay` keeps its std::net thread model (ADR-049) — its optional direct listener uses
   rustls's synchronous `ServerConnection`/`StreamOwned` (OPEN-M6-08 A); `secmp-client-core::scheduler::core` is sans-IO
   (time as arguments, randomness from `TimingRng`, no `tokio` path — X-09) and is the object of Kani, proptest and the
   virtual-clock activity-independence tests (OPEN-M6-11 A). Wall-clock reads stay in `secmp-client-core/src/clock.rs`
   (AD-11).
3. *API.* `AsyncQueueTransport` carries the seven §12.1 operations with `&mut self` and returns `impl Future + Send`
   (native async in traits, no `async-trait` crate); the M5 synchronous trait remains for the harness (OPEN-M6-10 A).
   Prepared frames: `Session::prepare` seals at prepare time, `write_prepared` writes only (AD-01, S-19).
4. *Gates.* Policy test `normal_dependencies_match_adr_allowlist` (F-7 of the M5 review, G-04) pins each crate's direct
   normal dependencies to this ADR's table; ADR-047 Amendment 4 (below) and the coverage/Kani lists follow OPEN-M6-23.

**Decision — Part 2 (OWNER class).** Direct dependencies, exact pins in `[workspace.dependencies]`, default features off:

| Crate | Pin (published) | Where | Why / features | Closure estimate (normal, Linux) | Vet route (proposal for the owner) |
|---|---|---|---|---|---|
| `arti-client` | `=0.46.0` (2026-09-02) | `secmp-transport` | Tor client, §12.3, ADR-007. Features `tokio`, `rustls`, `onion-service-client`, `static-sqlite`; not `compression`, `native-tls`, `hs-pow-full`, `experimental` (OPEN-M6-03) | ≈ 330 crates (37 `tor-*`/`arti-*`, `rusqlite` 0.39 + bundled SQLite, `futures-rustls`, `tokio-util`, `notify`, `async_executors`, older dalek/sha2/rand majors) | publisher trust, crate-scoped to `arti-client` and `tor-*`, for `nmathewson`, `ijackson`, `gabi-250`, `dgoulet-tor` (`end` ≤ 12 months); imported audits where they exist; the rest tracked exemptions naming `arti-client` |
| `rustls` | `=0.23.45` (2026-09-14) | `secmp-transport`, `secmp-relay` | TLS 1.3 client (direct mode) and the relay's direct listener; features `aws_lc_rs`, `std` (no `tls12` in our use; `futures-rustls` re-enables it in the graph, our configs restrict versions to TLS 1.3) | ≈ 10 (`rustls-webpki`, `rustls-pki-types`, `zeroize`, `subtle`, `once_cell`, `log`) | imported audit (0.23.45 is audited in an import set); `rustls-webpki`/`rustls-pki-types`: import or trust `ctz`/`djc` |
| `tokio-rustls` | `=0.26.5` (2026-09-04) | `secmp-transport` | rustls over tokio streams for the client TLS provider | 1 | trust `djc`, `quininer` (imports end at 0.24.0) — alternative: drive `rustls::ClientConnection` by hand and drop this crate |
| `tokio` | `=1.53.1` (2026-07-20; 1.53.2 of 2026-10-03 is inside the cooldown) | `secmp-transport`, `secmp-client-core`, `secmp-testkit` | async runtime (Part 1.1) | ≈ 6 (`mio`, `socket2`, `bytes`, `pin-project-lite`, `libc`/`windows-sys` already present) | trust `carllerche`, `Darksonn` (imports end at 1.42.1); `mio`, `socket2`: imports |
| `aws-lc-rs` | `=1.18.1` (2026-09-01; already in the workspace as a dev-dependency) | `secmp-transport`, `secmp-relay` (via `rustls` and as the explicit `CryptoProvider` source) | TLS crypto provider; X25519MLKEM768; `rustls`'s `aws_lc_rs` feature turns on `prebuilt-nasm` | `aws-lc-sys` 0.45.0 (C, build script) | existing trust `justsmth` (ADR-037; note already says "TLS in secmp-transport from M6"); build with NASM and `AWS_LC_SYS_PREBUILT_NASM=0` (OPEN-M6-06) |
| `turmoil` | `=0.7.2` (2026-04-24) | dev-dependency of `secmp-testkit` | network simulations (`docs/06` §4) | dev only | tracked exemption (dev, outside the normal closure), or trust `carllerche` |
| (not added) `async-trait`, `hickory-resolver`, any SOCKS crate, `rcgen`, `tracing-subscriber` | — | — | OPEN-M6-10, -26, -09, -25 | — | — |

Further owner decisions bundled here: license exceptions for `async_executors` (Unlicense) and `notify` (CC0-1.0) as
per-crate `[licenses] exceptions`, and the MPL-2.0 choice for `priority-queue` (OPEN-M6-05 B); `deny.toml` `skip` entries
for the duplicated versions, each with the pulling crate (OPEN-M6-04 A, engineering, listed here for completeness);
`arti-client`'s `static-sqlite` and the M7 consequence that `secmp-store` must share `rusqlite`/`libsqlite3-sys` majors
with Arti (`links = "sqlite3"`; OPEN-M6-03). CLAUDE.md §1.6 already exempts rustls/aws-lc-rs and Arti from the
"only `secmp-crypto` uses cryptographic crates" rule; they are never used for SecMP constructions (the SecMP-LINK layer
inside TLS and Tor is unchanged).

**Alternatives.** (a) C tor as a sidecar on the client instead of Arti: a second process and IPC, against ADR-007.
(b) `smol`/`async-std` instead of tokio: Arti supports them, turmoil does not, `docs/02` §4.1 names tokio.
(c) Owner delta audits of the whole Arti closure: ≈ 0.35 → 0.46 across 37 `tor-*` crates — not credible; publisher
trust plus tracked exemptions is the ADR-036 (2) pattern applied outside the crypto closure. (d) No relay TLS listener
in M6 (external terminator): the direct-TLS acceptance would rest on an unreviewed OpenSSL configuration.

**Consequences.** `Cargo.toml` `[workspace.dependencies]` gains the six pins (plus `secmp-relay`, `secmp-transport`,
`secmp-client-core` as workspace path entries, F-10); `supply-chain/` gains the owner's trust records and the tracked
exemptions of the Arti/tokio/rustls closure (each naming its direct dependency; reviewed at every release); `deny.toml`
gains the `skip` list and two license exceptions; CI installs NASM on Windows and sets `AWS_LC_SYS_PREBUILT_NASM=0`;
`cargo xtask cooldown` covers the larger lock; the expect lists change as OPEN-M6-23 says. **ADR-047 Amendment 4
(engineering, text to append):** "the mutation gate runs over `secmp-crypto`, `secmp-proto`, `secmp-relay`,
`secmp-client-core` and `secmp-transport` in the 8 shards of Amendment 1 with the per-package rule of Amendment 2;
`MUTANT_EXCLUDE_FILES` names only the Arti glue file(s) that need a live Tor network; M6 Phase B reports the CI time per
shard; the shard count changes only by a further amendment; test `mutants_scope_includes_client_core_and_transport`."
The §12.1 sketch (`#[async_trait]`, `&self`) is implemented as Part 1.3; an owner who reads that block as protocol text
records the reservation here.
