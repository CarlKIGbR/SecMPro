# Milestone report — M00 Repository bootstrap and engineering baseline

Branch: `m00-bootstrap` · Commit range: `e74acc1..` (in progress) · Author: Claude Code (Opus 5.5) · Date: 2026-09-28

Inputs: `docs/07-milestones.md` M0, kickoff prompt (`docs/prompts/kickoff-M0.md`), **Amendment A1** (owner/architect, 2026-09-28: macOS dev host, GitHub-hosted Linux + Windows gates for M0–M8, libvirt VM deferred to M9).

## 1. Plan (written before implementation, updated during)

Environment verified at start: `uname -m` = `arm64`, macOS 26.6.2, Apple M1 Pro; `rustc -vV` host `aarch64-apple-darwin`. No `sudo` → no Homebrew; host tools are installed user-locally under `~/.local/opt` (checksummed), Rust under `~/.rustup`/`~/.cargo` (shell profiles untouched).

| Step | What | Proves acceptance criterion / deliverable | Status |
|---|---|---|---|
| 1 | Toolchain and tools: Rust 1.98.1 (+ clippy, rustfmt, llvm-tools; targets linux-gnu, windows-msvc, aarch64-apple-darwin); pinned cargo tools (nextest, deny, vet, audit, auditable, cyclonedx, fuzz, mutants, llvm-cov, xwin, zigbuild); nightly-2026-09-21 (Miri, fuzz); Kani 0.68.0; ProVerif 2.05 built from the INRIA tarball (sha256 from opam); zig 0.16.0, LLVM 22.1.8 (= rustc's LLVM), CMake 4.4.3, NASM 3.02 | Prerequisite of every gate; versions in §6 | in progress |
| 2 | Git: `main` = docs baseline (`e74acc1`, pushed); branch `m00-bootstrap` | A1 §7 | done |
| 3 | ADRs: ADR-015 license (OQ-1 → AGPL-3.0-or-later), ADR-029 dev host / hosting / CI topology (OQ-3 + A1 §6), ADR-030 naming (OQ-2), OQ-17 recorded at ADR-026, ADR-031 xtask dependencies; ADR-027 status after spike (a) | Owner decisions recorded; D7 `LICENSE` + SPDX policy | |
| 4 | Workspace skeleton: root `Cargo.toml` (`[workspace.lints]` verbatim from `06` §2, release profile from `06` §6), `rust-toolchain.toml`, `clippy.toml`, `.cargo/config.toml`, 11 crates (doc comment: responsibility + allowed dependencies; `#![forbid(unsafe_code)]` everywhere except `secmp-sys-mem`/`secmp-sys-desktop`), `xtask/`, `fuzz/`, `formal/`, `vectors/`, `ref/README.md` (ADR-026 rule only), `deploy/`, `supply-chain/` | D1, D2 | |
| 5 | xtask policy checks: `forbid(unsafe_code)` grep over **every target root** of every non-`sys` crate; no build scripts in our crates; SPDX headers; 7-day cooldown (Cargo.lock × crates.io sparse-index `pubtime`, reference time = server `Date` header, fail closed); pinned-tool check; explicit expected input sets per gate (a gate whose inputs shrink fails) | D3, D4; review focus "cooldown check works", "nothing in CI can be skipped silently" | |
| 6 | xtask commands: `ci-fast` (06 §5 steps 1–5), `ci-full` (steps 1–14; `--strict` turns every skip into a failure, used in CI), `sbom`, `win-test --backend github` (real, via `gh`) / `--backend libvirt` (documented stub, required from M9), stubs `vectors`, `repro-check`, `ops-check`; unit tests for all parsers/policies | D4 | |
| 7 | `deny.toml` (crates.io only, bans, license allowlist incl. the Slint exception, no LGPL); `cargo vet init` + imports (Mozilla, Google, ISRG, Bytecode Alliance, Zcash); tracked-exemption procedure in `supply-chain/README.md` | D3; acceptance "deny + vet pass, zero exemptions in the `secmp-crypto`/`secmp-proto` closure (empty in M0)" | |
| 8 | CI (`.github/workflows/ci.yml`): `linux-fast` (steps 1–5, 13, 14) on `ubuntu-latest`; `windows-native` (build + tests, MSVC) on `windows-latest`; `xwin-cross` (`continue-on-error`, A1 §5); `linux-full` (`ci-full --strict`, schedule + dispatch); every action pinned by SHA; no `pull_request_target`/`workflow_run`; no caches shared with any release workflow | D5; Windows gate for M0 (A1 §2) | |
| 9 | Negative demonstrations: scratch crate with `unwrap()` → `ci-fast` fails; scratch crate with `unsafe` outside `secmp-sys-*` → `ci-fast` fails; outputs kept in `docs/reviews/M00-evidence/`; scratch crates removed | Acceptance: two negative demonstrations | |
| 10 | Spikes in `spikes/` (outside the workspace, removed afterwards): (a) `rusqlite` `bundled-sqlcipher-vendored-openssl` built and executed natively on `windows-latest`, cross-built with `cargo-xwin` from macOS and from the Linux runner; (b) `aws-lc-rs` likewise; (c) Slint hello-world compiled for macOS, Linux and Windows, opened natively on macOS. Outcomes in `docs/reviews/M0-spikes.md`; ADR-027 fallback proposed only if the native Windows build of (a) fails | D6; acceptance "spike outcomes recorded" | |
| 11 | `SECURITY.md`, `CHANGELOG.md` (Keep a Changelog, `Unreleased`), `LICENSE` (AGPL-3.0 text), `README.md` build instructions (macOS dev host, Linux, Windows) | D7 | |
| 12 | Gates: local `cargo xtask ci-full` on macOS; `ci-full --strict` green on `ubuntu-latest`; `windows-native` green, triggered and collected by `cargo xtask win-test --backend github`. libvirt VM gate: *deferred by owner decision (A1)* | Acceptance "`ci-full` green", Windows gate | |
| 13 | Complete this report (evidence, gates, deviations, dependencies, risks), `CHANGELOG.md`, open the PR; stop | DoD `06` §8 | |

## 2. What was built

(filled in at the end)

## 3. Evidence per acceptance criterion

(filled in at the end)

## 4. Gates

(filled in at the end)

## 5. Deviations from spec / plan

(filled in at the end)

## 6. Dependencies added or bumped

(filled in at the end)

## 7. Open risks and known limitations

(filled in at the end)

## 8. Blocked / questions for the reviewer or owner

(filled in at the end)

## 9. Checklist before requesting review

- [ ] All acceptance criteria evidenced above
- [ ] `cargo xtask ci` green on a clean checkout
- [ ] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [ ] Vectors frozen and reviewed (if changed) — n/a in M0
- [ ] Docs/CHANGELOG updated
- [ ] Threat model and spec untouched (or ADR'd)
