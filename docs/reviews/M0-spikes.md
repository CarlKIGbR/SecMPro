# M0 spikes — outcomes

Milestone M0 (docs/07), Amendment A1 §4. Date: 2026-09-28. Author: Claude Code (Opus 5.5).

The spike programs lived in `spikes/` (each its own Cargo workspace, outside the product workspace and its
`Cargo.lock`/deny/vet) and in the temporary workflow `.github/workflows/spikes.yml`; both were removed after this
record was written. They are preserved in git history (commit range noted in §5).

Toolchain everywhere: Rust 1.98.1 (`rust-toolchain.toml`). macOS host: Apple M1 Pro, macOS 26.6.2,
`aarch64-apple-darwin`; cross tools: cargo-xwin 0.23.1 with LLVM 22.1.8 (`clang-cl`, `lld-link`, `llvm-lib`), NASM
3.02, CMake 4.4.3.

## (a) SQLCipher — `rusqlite` 0.40.2 `bundled-sqlcipher-vendored-openssl`

The program keys a new database file, writes a row, reopens it with the right key (reads the row back) and with a
wrong key (must fail), checks that the file has no plaintext SQLite header and no plaintext row, and prints
`PRAGMA cipher_version` / `cipher_provider`. Resolved: `libsqlite3-sys` 0.38.2, `openssl-sys` 0.9.117,
`openssl-src` 300.6.1+3.6.3 (OpenSSL 3.6.3).

| Platform / build | Result | Evidence |
|---|---|---|
| macOS aarch64, native | **OK** — `cipher_version = 4.14.0 community; cipher_provider = openssl OpenSSL 3.6.3`; wrong key → "file is not a database"; 8192-byte file, no plaintext | local run, `SPIKE-A OK (macos aarch64)` |
| cargo-xwin from macOS → `x86_64-pc-windows-msvc` | **FAILED** — `openssl-src` runs OpenSSL's `Configure VC-WIN64A`, which refuses a non-Windows perl: *"This perl implementation doesn't produce Windows like paths … Please use an implementation that matches your building platform."* (OpenSSL's MSVC build also needs `nmake`) | `M00-evidence/spike-a-xwin-macos.log` |
| `windows-latest`, native MSVC (Strawberry Perl 5.42.0, `cc` finds `nmake`) | **OK** — same output as macOS: `cipher_version = 4.14.0 community; cipher_provider = openssl OpenSSL 3.6.3`, wrong key rejected, no plaintext; `SPIKE-A OK (windows x86_64)` | [run 36454074151](https://github.com/CarlKIGbR/SecMPro/actions/runs/36454074151), `M00-evidence/spikes-ci-run-36454074151.log` |
| Linux x86_64 (`ubuntu-latest`), native | **OK** — identical output; `SPIKE-A OK (linux x86_64)` | same run |
| cargo-xwin from Linux → `x86_64-pc-windows-msvc` | **FAILED** — same cause as from macOS (OpenSSL `Configure VC-WIN64A` refuses the non-Windows perl) | same run |

## (b) aws-lc-rs 1.18.1 (`aws-lc-sys` 0.45.0)

SHA-256("abc") known answer, X25519 agreement between two fresh keys, ML-KEM-768 encapsulate/decapsulate round
trip.

| Platform / build | Result | Evidence |
|---|---|---|
| macOS aarch64, native | **OK** — KAT, X25519, ML-KEM-768 (ciphertext 1088 bytes) | local run, `SPIKE-B OK (macos aarch64)` |
| cargo-xwin from macOS → `x86_64-pc-windows-msvc` | **OK** — builds a PE32+ x86-64 console executable; `aws-lc-sys` used its `cc` builder with `clang-cl` (no CMake), assembly objects present | `M00-evidence/spike-b-xwin-macos.log` |
| `windows-latest`, native MSVC | **OK** — KAT, X25519, ML-KEM-768; `SPIKE-B OK (windows x86_64)` | [run 36454074151](https://github.com/CarlKIGbR/SecMPro/actions/runs/36454074151) |
| Linux x86_64, native | **OK**; `SPIKE-B OK (linux x86_64)` | same run |
| cargo-xwin from Linux → `x86_64-pc-windows-msvc`, runner without NASM | **FAILED** — `aws-lc-sys: NASM command not found or failed to execute` (x86_64 Windows assembly needs NASM; the macOS host had NASM 3.02) | same run |
| cargo-xwin from Linux, with the distribution's NASM | *pending re-run* | |

Observation: under cargo-xwin, `CARGO_ENCODED_RUSTFLAGS` contains the `.cargo/config.toml` target flags
(`-C target-cpu=x86-64-v2 -C control-flow-guard`, listed twice — harmless), so the docs/06 §6 flags survive a
cross-build.

## (c) Slint 1.18.1 hello-world (winit backend, FemtoVG renderer, AccessKit)

A 360×120 window with one text; a 2-second timer reports its state, hides it and quits the event loop.

| Platform / build | Result | Evidence |
|---|---|---|
| macOS aarch64, native, **opened** | **OK** — `window visible after 2 s: true (size 720×240 physical, scale 2)`, closed, exit 0 | local run, `SPIKE-C OK (macos aarch64)` |
| cargo-xwin from macOS → `x86_64-pc-windows-msvc`, compile | **OK** — PE32+ x86-64 executable | `M00-evidence/spike-c-xwin-macos.log` |
| `windows-latest`, native, compile | **OK** — `spike-slint-hello.exe`, 10 718 208 bytes | [run 36454074151](https://github.com/CarlKIGbR/SecMPro/actions/runs/36454074151) |
| Linux x86_64, native, compile (with `libfontconfig1-dev`, `libxkbcommon-dev`) | **OK** — 23 553 552-byte executable | same run |

**Finding (affects M8, reported for the reviewer): `slint::slint!` cannot be used in a crate that declares
`#![forbid(unsafe_code)]`.** The macro expansion (`ItemTreeVTable_static`) contains `#[allow(unsafe_code)]`, which
rustc rejects under a crate-level `forbid` (error E0453, `M00-evidence/spike-c-forbid-e0453.log`). With the
workspace level `#![deny(unsafe_code)]` the same code compiles and runs. `secmp-ui` must carry
`#![forbid(unsafe_code)]` (CLAUDE.md §1.6, docs/06 §2) and may not have a build script (CLAUDE.md §1.9), which also
excludes `slint-build`; so, as written, `secmp-ui` can use neither Slint's compiled components nor its build-time
compiler. Options for the reviewer/owner (no decision taken): (1) `slint-interpreter` (loads `.slint` at run time;
no generated `unsafe` in our crate — API and a11y implications to be checked in the M8 spike); (2) an ADR that
sanctions macro-generated `#[allow(unsafe_code)]` from `slint!` in `secmp-ui` only (the crate would then use
`deny` instead of `forbid`, and the `forbid` grep would need a documented exception); (3) the egui fallback of
ADR-013, if it does not hit the same problem. This belongs to the M8 go/no-go spike; M0 only records it.

## ADR-027 (SQLCipher on Windows)

Per Amendment A1 §4 the ADR-027 fallback is proposed only if the **native** Windows build of (a) fails. It did
not fail: `rusqlite` 0.40.2 with `bundled-sqlcipher-vendored-openssl` builds and runs natively on `windows-latest`
(and on Linux and macOS). **The fallback is therefore not proposed; SQLCipher stays the primary store** (status
update recorded in ADR-027, pending reviewer approval).

What remains open is the **build route**, not the store: the vendored OpenSSL cannot be cross-built to MSVC with
cargo-xwin from Linux or macOS (OpenSSL's `VC-WIN64A` configuration needs a Windows perl and `nmake`). `02` §7
plans Windows builds cross-compiled from Linux, and `06` §5/§6 plans the two-builder reproducibility check on
Linux builders (M11). Options, for the owner/reviewer (no decision taken): (1) build Windows releases natively
on Windows (two independent Windows builders, or a Windows builder plus a Windows VM) and adapt the
reproducibility plan; (2) cross-build with a prebuilt, pinned OpenSSL for MSVC supplied through `OPENSSL_DIR`
(`bundled-sqlcipher` without `vendored-openssl`) — the prebuilt library then becomes a supply-chain input of its
own; (3) the ADR-027 sealed-column SQLite fallback, which needs no OpenSSL at all; (4) a different SQLCipher
crypto provider (not exposed by `libsqlite3-sys` today). ADR-027's clause "or cannot be made reproducible" makes
this an M11 question at the latest; it affects M7 (store) only if option (3) is chosen.

## 5. Provenance

*Filled in when the spikes are removed.*
