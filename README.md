# SecMPro

> **Pre-release — do not use.** SecMPro is under active development (milestone M1 of 12). Nothing here has been audited, the protocol and the code change without notice, and there are no releases. Do not use it for anything that matters.

A zero-trust, post-quantum, metadata-free desktop messenger (Linux + Windows) with its own protocol, **SecMP/1**, written in Rust.

- No accounts, no identifiers, no directories — contacts are made by out-of-band invitation and verified with a safety number.
- Every key agreement is a hybrid of X25519 and ML-KEM (FIPS 203); identity keys are Ed25519 ‖ ML-DSA-65.
- Messages travel as fixed-size cells at a constant rate over Tor to a relay that keeps ciphertext in RAM and cannot log, identify or correlate.
- The desktop client removes its windows from the operating system's screenshot and screen-recording APIs (Windows; Linux/Wayland on KDE Plasma ≥ 6.7, Hyprland, niri — these Linux exclusions are compositor settings, not a security boundary) and locks content by default on displays that cannot be protected (X11, GNOME, remote sessions).
- v1: one relay + two clients with every security function active. v1.1: peer-to-peer over per-contact onion endpoints with optional personal mailboxes.

**Status:** implementation milestone M1 (`secmp-crypto`: primitives and constructions). See `docs/07-milestones.md` and `CHANGELOG.md`.

## Documentation

Start with `docs/00-vision-and-scope.md` (document map) and `CLAUDE.md` (rules for the implementing agent). The normative protocol is `docs/03-protocol-spec.md`; the threat model is `docs/01-threat-model.md`; decisions are in `docs/08-decisions.md`. The reference implementation of the test vectors is a separate, independently written Python package (`docs/08-decisions.md` ADR-026) outside this repository; only its vector files are committed under `vectors/ref/`.

## Building

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.98.1 with clippy, rustfmt, llvm-tools and the targets `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`); `rustup` installs it on first use. All gates run through `cargo xtask` (`cargo xtask help`, details in `xtask/README.md`). Pinned tool versions live in `xtask/src/tools.rs`.

### Development host: macOS (Apple Silicon)

macOS is a development host only (ADR-029); v1 ships for Linux and Windows.

```
rustup toolchain install              # from rust-toolchain.toml
cargo xtask install-tools --nightly   # pinned cargo tools + nightly for Miri/fuzz (Kani runs its own setup)
cargo xtask ci-fast                   # after every logical unit
cargo xtask ci-full                   # before a milestone report; systemd-analyze is Linux-only and is reported as SKIP
cargo xtask win-test --backend github # the Windows gate on GitHub-hosted windows-latest (needs `gh` and a pushed branch)
```

Extra host tools for `ci-full`: `zig` 0.16.0 (Linux-target build via cargo-zigbuild), LLVM 22 (`clang-cl`, `lld-link`, `llvm-lib`) for cargo-xwin, CMake and NASM for C dependencies from M1 on, and ProVerif 2.05 built from source (`https://proverif.inria.fr/proverif2.05.tar.gz`, SHA-256 `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`; `./build -nointeract` with OCaml, ocamlfind and ocamlbuild). Set `SECMP_PROVERIF` if `proverif` is not on `PATH`.

### Linux (x86_64)

```
rustup toolchain install
cargo xtask install-tools --nightly
cargo xtask ci-full --strict          # all 14 steps; systemd-analyze and ProVerif must be installed
cargo build --release --locked -p secmp-relay -p secmp-cli -p secmp-ui
```

### Windows (x86_64, MSVC)

Native: install Rust with rustup and the Visual Studio Build Tools (MSVC, Windows SDK), then

```
rustup toolchain install
cargo xtask install-tools --set windows
cargo xtask step --strict clippy nextest doctest kat hello
```

Cross-build from Linux or macOS: `cargo xtask step windows-cross` (cargo-xwin; needs `clang-cl`, `lld-link`, `llvm-lib`; downloads the MSVC CRT and Windows SDK). The Windows gate for M0–M8 is GitHub-hosted `windows-latest`; from M9 an ephemeral libvirt Windows 11 VM (`cargo xtask win-test --backend libvirt`, `xtask/README.md`).

## License

AGPL-3.0-or-later (`LICENSE`, ADR-015). Every source file carries an SPDX header.

## Security

See `SECURITY.md`. Please do not open public issues for vulnerabilities.
