# A0 probe — ADR-055 dependency set (report only)

Date 2026-10-27 · `modell=claude-opus-5-5` · tree: `4700464` (`m07-client-core`) · No `Cargo.toml` or lock of the
repository changed. Method: `git archive HEAD` into the scratch directory `target/a0/ws` (gitignored), ADR-055 items 1
and 2 applied there only (`a0/a0_edit.py.txt`): workspace deps `rusqlite =0.39.0` (`default-features = false`,
`bundled-sqlcipher-vendored-openssl`) and `argon2 =0.6.0` (`default-features = false`, `alloc`, `zeroize`); edges
`secmp-store` → {`rusqlite`, `secmp-crypto`, `secmp-proto`}, `secmp-crypto` → `argon2`, and for the probe of the
unified graph `secmp-client-core` → `secmp-store` (`cfg(not(kani))`) and `secmp-testkit` → `secmp-store`. Raw outputs:
`docs/reviews/M07-evidence/a0/`.

## 1 · Resolved versions, new lock entries (`a0/cargo-lock.diff`, `a0/fuzz-lock.diff`)

| Crate | Version | Published (crates.io index `pubtime`) | Age on 2026-10-27 | In build graph | Build script | License |
|---|---|---|---|---|---|---|
| `argon2` | 0.6.0 | 2026-08-27T16:54:18Z | 60 d | yes (`secmp-crypto`) | no | MIT OR Apache-2.0 |
| `blake2` | 0.11.0 | 2026-08-26T13:23:38Z | 61 d | yes (`secmp-crypto`) | no | MIT OR Apache-2.0 |
| `password-hash` | 0.6.1 | 2026-04-08T01:00:26Z | 202 d | no (lock only: optional dep of `argon2`, feature off; `cargo tree -i password-hash --target all -e features`: nothing) | no | MIT OR Apache-2.0 |
| `phc` | 0.6.1 | 2026-03-09T21:55:56Z | 231 d | no (lock only, via `password-hash`) | no | Apache-2.0 OR MIT |
| `openssl-sys` | 0.9.117 | 2026-06-12T18:11:16Z | 136 d | yes (`secmp-store`, via `libsqlite3-sys`) | **yes** (`links = "openssl"`) | MIT |
| `openssl-src` | 300.6.1+3.6.3 | 2026-06-09T14:26:26Z | 139 d | yes (build-dependency of `openssl-sys`: C build of OpenSSL 3.6.3) | no (a library used by `openssl-sys`'s build script) | MIT/Apache-2.0 (OpenSSL itself Apache-2.0) |

Already in the lock (via `arti-client`): `rusqlite` 0.39.0 (2026-03-15), `libsqlite3-sys` 0.37.0 (2026-03-15, build
script, `links = "sqlite3"`), `base64ct` 1.8.3, `cpufeatures` 0.3.1 (both already in the crypto closure's lock).
Same six new entries in `fuzz/Cargo.lock` (plus the path package `secmp-store`). No newer `argon2` than 0.6.0 on
crates.io (`cargo search`).

Closures per `VET_CLOSURE_TARGETS` (`a0/closures-per-target.txt`), identical on `x86_64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, `aarch64-apple-darwin`: `secmp-crypto` gains `argon2`, `blake2`, `base64ct`, `cpufeatures`
0.3.1; `secmp-store` adds `rusqlite`, `libsqlite3-sys`, `openssl-sys`.

## 2 · Gates on the scratch tree (`a0/gates.txt`)

| Step | Result |
|---|---|
| `deny` | PASS (advisories, bans, licenses, sources ok; no new license exception) |
| `audit` | PASS — RustSec DB of 2026-10-27, 1380 advisories, 577 lock crates; ignores unchanged (the five of `AUDIT_IGNORES`) |
| `cooldown` | PASS — 567 registry packages (561 at `4700464` + 6), all ≥ 7 days; youngest of the whole lock `rustls-webpki` 0.103.16 (7 d), youngest new entry `argon2` 0.6.0 (60 d) |
| `vet` | FAIL as expected: 6 unvetted — `argon2:0.6.0`, `blake2:0.11.0`, `openssl-src:300.6.1+3.6.3`, `openssl-sys:0.9.117`, `password-hash:0.6.1`, `phc:0.6.1` (all `safe-to-deploy` missing). `rusqlite`/`libsqlite3-sys` keep their tracked exemptions through `arti-client`. |

## 3 · Feature unification and the bundled C code

`cargo tree -i libsqlite3-sys -e features --target all --depth 2` (`a0/tree-libsqlite3-features-d2.txt`): features
`bundled`, `bundled-sqlcipher`, `bundled-sqlcipher-vendored-openssl`, `bundled_bindings`, `cc`, `default`,
`min_sqlite_version_3_34_1`, `openssl-sys`, `pkg-config`, `vcpkg`; `rusqlite` features `bundled`,
`bundled-sqlcipher`, `bundled-sqlcipher-vendored-openssl`, `cache`, `default`, `hashlink`, `modern_sqlite`, `time`
(`default`, `modern_sqlite`, `time` from Arti's side). One `libsqlite3-sys` for the whole graph, Arti's included.

Read back from the built library (`a0/a0-cipher-version.txt`, scratch test `a0_cipher_version`):
`PRAGMA cipher_version` = **`4.10.0 community`**, `sqlite_version()` = **3.50.4**, `cipher_provider` = `openssl`,
`cipher_provider_version` = **`OpenSSL 3.6.3 9 Jun 2026`**. Note for ST-02: the pragma string carries the suffix
` community`; the version check must parse the leading `MAJOR.MINOR.PATCH`.

## 4 · Arti's state DB under the SQLCipher build (ADR-055 item 3)

Scratch example `a0_arti_state` (`a0/a0_arti_state.rs.txt`): `TorClient::create_unbootstrapped` on
`secmp_transport::tor::config(profile)` — **no bootstrap, no network** — twice per build.

| Run | Result |
|---|---|
| SQLCipher build, fresh directory, then reopened | creates `tor/cache/dir.sqlite3` (65 536 B, header `53514c69746520666f726d6174203300` = `SQLite format 3\0`, i.e. a plain, unkeyed SQLite file), `dir.lock`, `state/state.lock`; reopen OK |
| plain-SQLite build of `4700464` (second scratch copy `target/a0/plain`), fresh directory | same three files, same header |
| SQLCipher build reopening the directory the plain build wrote (`A0_KEEP=1`) | OK (`a0/a0-arti-report-reopen.txt`) |
| that `dir.sqlite3` opened read-only without a key by the SQLCipher-built `rusqlite` | `integrity_check=ok`, `user_version=0`, tables `Authcerts, BridgeDescs, Consensuses, ExtDocs, Microdescs, ProtocolStatus, RouterDescs, TorSchemaMeta` (`a0/a0-arti-db.txt`) |
| `cargo nextest run -p secmp-transport -p secmp-store` (scratch) | 54 passed |
| harness `m6_tor::*`, `m6_sim_restart::*` (scratch, `--features harness`) | 5 passed |

Not done here: the `tor-smoke` dispatch (real Tor bootstrap, MR-07) — it needs the network and a dispatch run, which
the executor cannot start (`gh` read-only).

## 5 · fuzz workspace and sanitizer build (`a0/fuzz-lock.diff`, `a0/fuzz-run2.txt`)

- `fuzz/Cargo.lock` resolves with the same six new entries plus `secmp-store`; `cargo +nightly-2026-09-21 metadata
  --manifest-path fuzz/Cargo.toml` exit 0.
- `cargo +nightly-2026-09-21 fuzz build --fuzz-dir fuzz scheduler_event_sequence` (the existing target, which now
  pulls the store through `secmp-client-core`): exit 0, OpenSSL and SQLCipher compiled (1 min 56 s).
- Scratch target `a0_store` (`a0/a0_store.rs.txt`: an in-memory SQLCipher DB keyed from the input, one insert),
  cargo-fuzz default sanitizer (ASan): build exit 0; `nm` finds 597 `sqlcipher_`/`EVP_`/`__asan_` symbols; 5 000 runs,
  `cov: 290 ft: 431`, no ASan or LeakSanitizer report. The C code is compiled by `cc` without sanitizer
  instrumentation (cargo-fuzz sets no `CFLAGS`); it is linked and executed under the instrumented Rust code.

## 6 · Not covered by this probe

1. **Native Windows build (`windows-latest`)** — needs a dispatch or PR run; the executor cannot push or dispatch.
2. **Upstream advisories for SQLite 3.50.4, SQLCipher 4.10.0, OpenSSL 3.6.3** — the RustSec DB shows none for the
   crates `libsqlite3-sys` 0.37.0, `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3; the vendor CVE lists (sqlite.org,
   zetetic, openssl-library.org) could not be read: the container has no web access (fetch refused by the proxy).
3. **`tor-smoke` with a real bootstrap** (§4).
4. **`cargo-xwin`** of the unified graph — excluded by ADR-034 Amendment 1. Open point for G7-06 (report §8, Q-A1):
   `secmp-crypto` and `secmp-transport` dev-depend on `secmp-testkit`, so a `--workspace --all-targets` xwin build
   still compiles the testkit (and, after G7-06, the store and vendored OpenSSL) as a dev-dependency of non-excluded
   packages.

## 7 · Verdict lines

- A0 red conditions (ADR-055): unification breaks Arti — **no** (§4, without bootstrap); crate < 7 days — **no**
  (youngest new 60 d); RustSec advisory — **none**; license outside the allowlist — **no** (`cargo deny` licenses ok).
- SQLCipher pin candidate for `expect::SQLCIPHER_MIN`: **4.10.0** (pragma `4.10.0 community`), SQLite 3.50.4,
  OpenSSL 3.6.3.
- Vet records needed (owner, ADR-055 item 5): `argon2` 0.6.0, `blake2` 0.11.0 (zero-exemption crypto closure);
  `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3, `password-hash` 0.6.1, `phc` 0.6.1 (record or tracked exemption).
