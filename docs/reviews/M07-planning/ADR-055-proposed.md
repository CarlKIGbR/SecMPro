### ADR-055 — M7 dependency set: `rusqlite` with bundled SQLCipher/OpenSSL in `secmp-store`, `argon2` in `secmp-crypto`

**Status.** Proposed (planner, 2026-10-27; M7 planning, OPEN-M7-03, reviewer decision Q82). **OWNER class** (shipped
dependencies, `cargo vet` records by a named human, build inputs; CLAUDE.md §1.9, `docs/06:65`). **Ratification
precondition:** the Phase A step A0 probe report (below) is delivered and read by the reviewer; then the owner writes
"ADR-055 accepted" and records the vet entries. No `Cargo.toml` change before both. Extends ADR-020, ADR-027 (M0 outcome),
ADR-051 (`docs/08:797`: `secmp-store` must share Arti's `rusqlite`/`libsqlite3-sys` majors).

**Context.** `Cargo.lock` holds `rusqlite` 0.39.0 (`:3302`) and `libsqlite3-sys` 0.37.0 (`:2321`, deps `cc`, `pkg-config`,
`vcpkg`, no OpenSSL) through `arti-client` 0.46.0 feature `static-sqlite` (`Cargo.toml:64`); both are only tracked
exemptions (`supply-chain/config.toml:722,1032`). `libsqlite3-sys` declares `links = "sqlite3"`, so the graph can hold
one version. `libsqlite3-sys` 0.37.0 bundles **SQLCipher 4.10.0** (SQLite 3.50.4;
`sqlcipher/sqlite3.c:108426` `#define CIPHER_VERSION_NUMBER 4.10.0`, verifier read of the crate source) — older than the
M0 spike (4.14.0 with `rusqlite` 0.40.2, ADR-027 `docs/08:149`) and than CS-3.1's "4.17.0 at the time of writing"
(`docs/04:52`), which asks for a start-up check against a pinned version. `argon2` is absent from the lock; `docs/06` §3 lists it among the
crates allowed only in `secmp-crypto`.

**Decision.**
1. *`secmp-store`* gains `rusqlite` at **exactly the version Arti resolves** (0.39.0 at `bf55099`) with
   `default-features = false, features = ["bundled-sqlcipher-vendored-openssl"]` (no other feature). This enables in
   `libsqlite3-sys` 0.37.0 the features `bundled-sqlcipher` and `bundled-sqlcipher-vendored-openssl`, which add
   `openssl-sys` and `openssl-src` (C build of OpenSSL 3, build scripts) — exact versions = those of the A0 probe.
2. *`secmp-crypto`* gains `argon2` (exact pin; 0.6.0 of 2026-08-27 unless A0 finds a newer one ≥ 7 days old;
   `default-features = false`, features `alloc`, `zeroize`); its non-optional dependencies `blake2`, `base64ct` (already
   trusted, `supply-chain/audits.toml:112`) and `cpufeatures` 0.3 enter the crypto closure; only `secmp-crypto` uses them.
3. *Unification consequence for Arti.* Features unify across the graph: Arti's state database is then built against
   SQLCipher instead of plain SQLite. Arti opens it without a key; SQLCipher without a key reads and writes plain SQLite
   files. CS-3.6 (`docs/04:57`) says Tor state is not secret, so nothing is lost; the A0 probe must show Arti's
   bootstrap with an existing state dir and with a fresh one still works (tokio-paused loopback test + `tor-smoke`).
4. *Version pin (Q119).* `expect::SQLCIPHER_MIN` = **4.10.0**, the one version the graph can hold (`links = "sqlite3"`,
   Arti's); ST-02 refuses < 4.10.0 and accepts 4.10.0. The pin moves with Arti. CS-3.1's "4.17.0" is an owner point (memo):
   accept 4.10.0 as the M7 pin. A0 checks SQLCipher 4.10.0 / SQLite 3.50.4 / the vendored OpenSSL for open advisories.
5. *`cargo vet` records.* The direct deps `rusqlite` (of `secmp-store`) and `argon2` (of `secmp-crypto`) need an audit or
   trust record **recorded by the owner** (named human; `docs/06:65`); their transitive deps in the zero-exemption crypto
   closure (`blake2`, `cpufeatures`; ADR-036, `docs/06:68`) need imports, RustCrypto publisher trust or owner delta
   audits — no exemption; `libsqlite3-sys`, `openssl-sys`, `openssl-src` (outside that closure) need a record or a tracked
   exemption naming `rusqlite`; the reviewer's verifier reads the crates/deltas (Q72 precedent), the owner ratifies with one
   sentence. xtask's `miniz_oxide` (OPEN-M7-21) is asked for in the same memo item.
6. *Gates.* `NORMAL_DEPENDENCY_ALLOW` (`xtask/src/expect.rs:35-66`) and the ADR-051 third-party table checked by
   `normal_dependencies_match_adr_allowlist` (`policy.rs:2434-2462`), always in the same commit: full rows `secmp-store`,
   `secmp-crypto` (14 deps + `argon2`) in A-2 (G7-01); store edges of client-core/testkit in A-3 (G7-06); `secmp-cli` in C (G7-21); `deny.toml` licenses: OpenSSL (Apache-2.0),
   SQLCipher (BSD-3-Clause) are in the allowlist — no new exception; cooldown ≥ 7 days for every new lock entry.

**A0 probe (precondition, report only, scratch crate outside the workspace).** Resolve the workspace pins + item 1 + item
2 for the three targets of `VET_CLOSURE_TARGETS`, **and the same for `fuzz/Cargo.lock`** (the fuzz workspace gains
`argon2` and, through client-core, the SQLCipher/OpenSSL C build: build one fuzz target under cargo-fuzz's sanitizer
flags); report: resolved versions, new lock entries with publish dates, build
scripts, license set, `cargo tree -i libsqlite3-sys -e features`, bundled SQLCipher version, Arti state-DB smoke result,
native Windows build (`windows-latest`) result. A0 red (unification breaks Arti, a crate < 7 days, an advisory, a license
outside the allowlist) = STOP; the reviewer then chooses between a store-local alternative and the ADR-027 fallback.

**Alternatives.** (a) `rusqlite` 0.40.x as in the spike — impossible beside Arti's 0.39 (`links`). (b) System SQLCipher
via `pkg-config` — not reproducible, absent on Windows. (c) ADR-027 fallback — kept as the STOP branch.

**Consequences.** `xwin-cross` cannot cross-build vendored OpenSSL (ADR-027 M0 outcome): ADR-034 amendment excludes the
store-dependent crates there (OPEN-M7-04); `secmp-store` is `cfg(not(kani))` in `secmp-client-core` (OPEN-M7-05); the
reproducibility risk of the C builds is tracked for M11 (`docs/06` §6).
