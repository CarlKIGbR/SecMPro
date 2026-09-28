# Milestone report — M00 Repository bootstrap and engineering baseline

Branch: `m00-bootstrap` · Commit range: `e74acc1..` (base `e74acc1` = docs baseline on `main`; final code state `58dc402`, followed only by this report/CHANGELOG commit) · Author: Claude Code (Opus 5.5) · Date: 2026-09-28

Inputs: `docs/07-milestones.md` M0, kickoff prompt (`docs/prompts/kickoff-M0.md`), **Amendment A1** (owner/architect, 2026-09-28: macOS dev host, GitHub-hosted Linux + Windows gates for M0–M8, libvirt VM deferred to M9).

## 1. Plan (written before implementation, updated during)

Environment verified at start: `uname -m` = `arm64`, macOS 26.6.2, Apple M1 Pro; `rustc -vV` host `aarch64-apple-darwin`. No `sudo` → no Homebrew; host tools are installed user-locally under `~/.local/opt` (checksummed), Rust under `~/.rustup`/`~/.cargo` (shell profiles untouched).

| Step | What | Proves acceptance criterion / deliverable | Status |
|---|---|---|---|
| 1 | Toolchain and tools: Rust 1.98.1 (+ clippy, rustfmt, llvm-tools; targets linux-gnu, windows-msvc, aarch64-apple-darwin); pinned cargo tools (nextest, deny, vet, audit, auditable, cyclonedx, fuzz, mutants, llvm-cov, xwin, zigbuild); nightly-2026-09-21 (Miri, fuzz); Kani 0.68.0; ProVerif 2.05 built from the INRIA tarball (sha256 from opam); zig 0.16.0, LLVM 22.1.8 (= rustc's LLVM), CMake 4.4.3, NASM 3.02 | Prerequisite of every gate; versions in §6 | done |
| 2 | Git: `main` = docs baseline (`e74acc1`, pushed); branch `m00-bootstrap` | A1 §7 | done |
| 3 | ADRs: ADR-015 license (OQ-1 → AGPL-3.0-or-later), ADR-029 dev host / hosting / CI topology (OQ-3 + A1 §6), ADR-030 naming (OQ-2), OQ-17 recorded at ADR-026, ADR-031 xtask dependencies; ADR-027 status after spike (a) | Owner decisions recorded; D7 `LICENSE` + SPDX policy | done |
| 4 | Workspace skeleton: root `Cargo.toml` (`[workspace.lints]` verbatim from `06` §2, release profile from `06` §6), `rust-toolchain.toml`, `clippy.toml`, `.cargo/config.toml`, 11 crates (doc comment: responsibility + allowed dependencies; `#![forbid(unsafe_code)]` everywhere except `secmp-sys-mem`/`secmp-sys-desktop`), `xtask/`, `fuzz/`, `formal/`, `vectors/`, `ref/README.md` (ADR-026 rule only), `deploy/`, `supply-chain/` | D1, D2 | done |
| 5 | xtask policy checks: `forbid(unsafe_code)` grep over **every target root** of every non-`sys` crate; no build scripts in our crates; SPDX headers; 7-day cooldown (Cargo.lock × crates.io sparse-index `pubtime`, reference time = server `Date` header, fail closed); pinned-tool check; explicit expected input sets per gate (a gate whose inputs shrink fails) | D3, D4; review focus "cooldown check works", "nothing in CI can be skipped silently" | done |
| 6 | xtask commands: `ci-fast` (06 §5 steps 1–5), `ci-full` (steps 1–14; `--strict` turns every skip into a failure, used in CI), `sbom`, `win-test --backend github` (real, via `gh`) / `--backend libvirt` (documented stub, required from M9), stubs `vectors`, `repro-check`, `ops-check`; unit tests for all parsers/policies | D4 | done |
| 7 | `deny.toml` (crates.io only, bans, license allowlist incl. the Slint exception, no LGPL); `cargo vet init` + imports (Mozilla, Google, ISRG, Bytecode Alliance, Zcash); tracked-exemption procedure in `supply-chain/README.md` | D3; acceptance "deny + vet pass, zero exemptions in the `secmp-crypto`/`secmp-proto` closure (empty in M0)" | done |
| 8 | CI (`.github/workflows/ci.yml`): `linux-fast` (steps 1–5, 13, 14) on `ubuntu-latest`; `windows-native` (build + tests, MSVC) on `windows-latest`; `xwin-cross` (`continue-on-error`, A1 §5); `linux-full` (`ci-full --strict`; schedule, dispatch, pull requests and milestone-branch pushes); every action pinned by SHA; no `pull_request_target`/`workflow_run`; no caches shared with any release workflow | D5; Windows gate for M0 (A1 §2) | done |
| 9 | Negative demonstrations: scratch crate with `unwrap()` → `ci-fast` fails; scratch crate with `unsafe` outside `secmp-sys-*` → `ci-fast` fails; outputs kept in `docs/reviews/M00-evidence/`; scratch crates removed | Acceptance: two negative demonstrations | done (local + CI runs 36458107077, 36458696523; removed) |
| 10 | Spikes in `spikes/` (outside the workspace, removed afterwards): (a) `rusqlite` `bundled-sqlcipher-vendored-openssl` built and executed natively on `windows-latest`, cross-built with `cargo-xwin` from macOS and from the Linux runner; (b) `aws-lc-rs` likewise; (c) Slint hello-world compiled for macOS, Linux and Windows, opened natively on macOS. Outcomes in `docs/reviews/M0-spikes.md`; ADR-027 fallback proposed only if the native Windows build of (a) fails | D6; acceptance "spike outcomes recorded" | done (spikes removed in 58dc402) |
| 11 | `SECURITY.md`, `CHANGELOG.md` (Keep a Changelog, `Unreleased`), `LICENSE` (AGPL-3.0 text), `README.md` build instructions (macOS dev host, Linux, Windows) | D7 | done |
| 12 | Gates: local `cargo xtask ci-full` on macOS; `ci-full --strict` green on `ubuntu-latest`; `windows-native` green, triggered and collected by `cargo xtask win-test --backend github`. libvirt VM gate: *deferred by owner decision (A1)* | Acceptance "`ci-full` green", Windows gate | done (run 36461122501; win-test github) |
| 13 | Complete this report (evidence, gates, deviations, dependencies, risks), `CHANGELOG.md`, open the PR; stop | DoD `06` §8 | done (PR opened) |

## 2. What was built

| Area | Files | Source of the requirement |
|---|---|---|
| Workspace | `Cargo.toml` (`[workspace.lints]` verbatim from `06` §2, `[profile.release]` from `06` §6, `[workspace.package]` license AGPL-3.0-or-later, `publish = false`), `Cargo.lock`, `rust-toolchain.toml` (1.98.1; clippy, rustfmt, llvm-tools; targets `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`), `clippy.toml` (disallowed `rand::thread_rng`, `SystemTime::now`; `doc-valid-idents`), `.cargo/config.toml` (`xtask` alias; `-C target-cpu=x86-64-v2` for both x86_64 targets, `-C control-flow-guard` for MSVC), `.gitignore`, `LICENSE` | `02` §3, `06` §1–2, §6, OQ-1 |
| 11 crates | `crates/secmp-{crypto,proto,transport,store,client-core,relay,cli,ui,sys-mem,sys-desktop,testkit}`: crate doc = responsibility + allowed dependencies (`02` §3); `#![forbid(unsafe_code)]` in all but the two `secmp-sys-*`; no code except the three binaries (`secmp-relay`, `secmp-cli`, `secmp-ui`), which print `<name> <version> (M0 skeleton: no functionality)` — the hello-world — each with one integration test (`tests/hello.rs`) | `07` M0 D1 |
| Directories | `fuzz/`, `formal/`, `vectors/`, `deploy/` (README each, input sets listed in `xtask/src/expect.rs`), `ref/README.md` (ADR-026 rule only, nothing else), `supply-chain/` | `07` M0 D1, OQ-17 |
| `xtask` | `ci-fast`, `ci-full`/`ci`, `step`, `policy`, `cooldown`, `sbom`, `win-test --backend github\|libvirt`, `install-tools`, stubs `vectors`/`repro-check`/`ops-check` (exit non-zero); 3 491 lines, 29 unit tests; README | `07` M0 D3–D4, `06` §5, A1 §2 |
| Supply chain | `deny.toml`; `supply-chain/{config.toml,audits.toml,imports.lock}` (`cargo vet init`, 5 imports, 10 tracked exemptions with notes); `supply-chain/README.md` (acceptance + tracked-exemption procedure) | `07` M0 D3, `06` §3 |
| CI | `.github/workflows/ci.yml`: `linux-fast` (steps 1–5, 13, 14), `windows-native` (Windows gate), `xwin-cross` (`continue-on-error`, A1 §5), `linux-full` (`ci-full --strict`); temporary `spikes.yml` (removed with the spikes) | `07` M0 D5, A1 §5 |
| Spikes | `spikes/{sqlcipher,aws-lc,slint-hello}` (removed after recording), `docs/reviews/M0-spikes.md` | `07` M0 D6, A1 §4 |
| Docs | `SECURITY.md`, `CHANGELOG.md`, `README.md` (build instructions macOS/Linux/Windows), `docs/08-decisions.md` (ADR-015/026 updates, ADR-029–032), this report, `docs/reviews/M00-evidence/` | `07` M0 D7 |

No protocol or cryptographic code was written (nothing from M1 was prepared).

## 3. Evidence per acceptance criterion

Raw outputs are in `docs/reviews/M00-evidence/` (home directories redacted to `~`). CI runs are on the private repository `CarlKIGbR/SecMPro`.

| Criterion (`07` M0 + kickoff §5) | Test / command | Result |
|---|---|---|
| `cargo xtask ci-full` green on the empty workspace | **Linux (authoritative):** CI job `linux-full`, `cargo xtask ci-full --strict --delegated windows-native --delegated windows-cross`, run [36461122501](https://github.com/CarlKIGbR/SecMPro/actions/runs/36461122501) @ `58dc402` (first green: run [36454074199](https://github.com/CarlKIGbR/SecMPro/actions/runs/36454074199) @ `1ca8a00`). The two delegated steps are jobs `windows-native` and `xwin-cross` of the same run, both green. **macOS dev host:** `cargo xtask ci-full` | Linux, `--strict`: 24 steps = **20 PASS, 2 DELEGATED (green jobs), 2 STUB** (`ref-vectors` → M1, `repro` → M11), **0 SKIP** → `ci-full: PASS` (`ci-final-run-36461122501.log`). macOS: 20 PASS, 2 STUB, 2 SKIP (`windows-native` → CI job, `systemd` → Linux-only) → "PASS with 2 host-specific skip(s)" (`ci-full-macos.log`) |
| `cargo deny check` passes | `cargo deny --locked check` (cargo-deny 0.20.2); also step `deny` in every CI run | `advisories ok, bans ok, licenses ok, sources ok`; 8 warnings only: 7 allowed licences and the Slint exception not yet encountered (`deny-vet-local.log`) |
| `cargo vet` passes with zero exemptions in the `secmp-crypto`/`secmp-proto` closure | `cargo vet --locked` (cargo-vet 0.10.2); `cargo xtask policy` (vet-closure); `cargo tree -p secmp-crypto -p secmp-proto -e all` | `Vetting Succeeded (1 fully audited, 10 exempted)`. **The closure is empty in M0**: neither crate has any dependency (`cargo tree` prints only the crate itself), so it has 0 crates and 0 exemptions. The 10 exemptions are tracked exemptions of `xtask`-only crates (§6, §8 Q1) |
| A scratch crate containing `unwrap()` fails CI (demonstrated, then removed) | commit `1e8bd75` (crate `scratch-unwrap`, otherwise compliant) → run [36458107077](https://github.com/CarlKIGbR/SecMPro/actions/runs/36458107077); local `cargo xtask ci-fast` | CI **failure**: `linux-fast` (clippy: ``used `unwrap()` on an `Option` value`` at `crates/scratch-unwrap/src/lib.rs:11:5`), `windows-native` (clippy), `linux-full` (clippy + coverage); `xwin-cross` green because it only compiles (`negative-unwrap-ci.log`, `negative-unwrap-local.log`). Removed in `bab5320` |
| A scratch crate containing `unsafe` outside `secmp-sys-*` fails CI (demonstrated, then removed) | commit `bab5320` (crate `scratch-unsafe`: `unsafe fn` + `unsafe` block, no `forbid`) → run [36458696523](https://github.com/CarlKIGbR/SecMPro/actions/runs/36458696523); local `cargo xtask ci-fast` | CI **failure in all four jobs**: rustc `unsafe_code = deny` (``declaration of an `unsafe` function``, ``usage of an `unsafe` block``) breaks clippy, nextest, doctest, coverage and the xwin build, and the policy grep reports `lacks #![forbid(unsafe_code)]` (`negative-unsafe-ci.log`, `negative-unsafe-local.log`). Removed in `58dc402` |
| ⚙ Windows hello-world runs via `cargo xtask win-test` | `cargo xtask win-test --backend github` (Amendment A1 §2) on commit `58dc402` → run [36461122501](https://github.com/CarlKIGbR/SecMPro/actions/runs/36461122501), job `windows-native` (`windows-latest`, `x86_64-pc-windows-msvc`, Rust 1.98.1, MSVC) | **PASS**: clippy `-D warnings` clean; `32 tests run: 32 passed` (29 xtask unit tests + the three `tests/hello.rs`); `hello-world: secmp-relay 0.0.0 …`, `secmp-cli …`, `secmp-ui …`; job concluded `success` (`win-test-github-run-36461122501.log`). **`--backend libvirt`: deferred by owner decision (A1)** — mechanism documented in `xtask/README.md`, required from M9; not claimed to have run |
| Spike outcomes recorded | `docs/reviews/M0-spikes.md` | (a) SQLCipher: native OK on `windows-latest`, Linux, macOS; xwin cross fails (OpenSSL needs a Windows perl) → ADR-027 fallback **not** triggered (A1 §4). (b) aws-lc-rs: native OK on all three; xwin cross OK from macOS and from Linux (with NASM). (c) Slint: window opens/closes on macOS; compiles for Linux and Windows; `slint!` incompatible with `forbid(unsafe_code)` (E0453) — M8 finding |

Deliverables (`07` M0 / kickoff §5): D1 workspace + 11 crates + directories ✔ (§2); D2 `rust-toolchain.toml`, `[workspace.lints]`, `clippy.toml`, `.cargo/config.toml` ✔ (remap: D-1); D3 `deny.toml`, `supply-chain/` with imports + procedure, cooldown check ✔; D4 xtask commands incl. `forbid` grep and cooldown ✔ (`win-test` github real, libvirt documented/deferred); D5 CI steps 1–5, 13, 14 on Linux, Windows jobs, hygiene rules ✔ (enforced by `policy`); D6 spikes ✔; D7 `SECURITY.md`, `CHANGELOG.md`, `docs/reviews/`, `LICENSE`, `README.md` ✔.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci` (Linux) | **green** — `ci-full --strict`, run [36461122501](https://github.com/CarlKIGbR/SecMPro/actions/runs/36461122501) (all four jobs `success`) |
| Windows (A1: `windows-latest` for M0–M8) | **green** — job `windows-native`, run 36461122501, via `cargo xtask win-test --backend github`; libvirt VM: deferred by owner decision (M9) |
| cargo-xwin cross-build (`continue-on-error` allowed in M0) | **green** in every run without a deliberate failure (180 s in run 36461122501); never needed the allowance |
| KATs / differential | n/a in M0 — gate active, expected package set empty (`xtask/src/expect.rs`) |
| Fuzz smoke | n/a in M0 — tool + nightly checked, 0 targets (expected 0) |
| Mutation (`cargo mutants`) | `Found 0 mutants to test` for `secmp-crypto`, `secmp-proto` (no code) |
| Coverage | `secmp-relay`, `secmp-cli`, `secmp-ui` 5/6 lines = 83.3 % each (≥ 80 %); all other crates contain no code |
| ProVerif / Kani / Miri | ProVerif 2.05 self-test [true, false] ok, 0 models (expected 0); Kani 0.68.0 ready, 0 harnesses (expected 0); Miri (nightly-2026-09-21) on `secmp-sys-mem`, `secmp-sys-desktop`, `secmp-crypto` — pass (no code) |
| `cargo deny` / `cargo vet` / `cargo audit` / cooldown | pass / pass (1 audited, 10 tracked exemptions, closure empty) / pass (`--deny warnings`) / pass (11 registry packages, youngest 11 days) |
| SBOM (step 13) | 12 CycloneDX SBOMs; auditable release builds of the three binaries read back by `cargo audit bin`; no local path in the binaries (macOS check) |
| systemd exposure (step 14) | systemd 255: unhardened fixture 9.4 > 2.0 rejected (self-test); 0 units (M10) |
| Reproducible build | stub until M11 (`cargo xtask repro-check` exits non-zero by design) |

## 5. Deviations from spec / plan

Spec (`03`) and threat model (`01`) are untouched. `docs/00–07` and `docs/09` are untouched; `docs/08` received only the owner-decided updates and the new ADRs.

| # | Item | Status |
|---|---|---|
| D-1 | `06` §6 asks for `--remap-path-prefix` of `$CARGO_HOME` and the workspace "fixed in `.cargo/config.toml`". Cargo 1.98.1 does not expand variables in config values and `trim-paths` is unstable (verified: `cargo +1.98.1 build` with `trim-paths` → "feature `trim-paths` is required"). The static flags are in `.cargo/config.toml`; `cargo xtask` appends the two remap flags for release builds via `--config target.<triple>.rustflags=[…]` (Cargo merges arrays). Verified: the three auditable release binaries contain no `/Users/` path (`strings … \| grep -c /Users/` = 0). | **ADR-032, proposed** — needs reviewer approval |
| D-2 | Windows gate on GitHub-hosted `windows-latest` instead of the libvirt VM; macOS as development host. | Owner decision, Amendment A1 → ADR-029 (not a deviation) |
| D-3 | `docs/06` §5 step 14 needs `deploy/secmp-relay.service`, which is an M10 deliverable. The gate is implemented and self-tested (an unhardened fixture must score > 2.0 and be rejected on every run); its expected unit set is empty until M10. No M10 work was pulled forward. | Plan inconsistency, reported (§8 Q4) |

Implementation notes the reviewer may want to check (conforming, not deviations): the workspace denies the `print!` family, so `xtask` and the three hello-world binaries write with `writeln!(std::io::stdout().lock(), …)` and handle the error; `xtask` never calls `SystemTime::now` (the cooldown uses the crates.io `Date` header); there are zero `#[allow]`/`#[expect]` attributes in the repository (the `policy` step enforces that each one is sanctioned).

## 6. Dependencies added or bumped

Direct dependencies of the product workspace (all checked against the 7-day cooldown on 2026-09-28):

| Crate | Version | ADR | Vet record | Reason |
|---|---|---|---|---|
| `serde_json` (xtask only; `default-features = false`, `std`) | =1.0.151 (2026-07-20) | ADR-031 (proposed) | tracked exemption | JSON of `cargo metadata`, llvm-cov, crates.io index, `gh` |

Transitive registry crates in `Cargo.lock` (all via `xtask`; none in the `secmp-crypto`/`secmp-proto` closure, which is **empty**): `serde_core` 1.0.229, `itoa` 1.0.18, `memchr` 2.8.3, `zmij` 1.0.23 and, through `serde_core`'s `cfg(any())` version lock (never compiled), `serde` 1.0.229, `serde_derive` 1.0.229, `syn` 3.0.6, `quote` 1.0.47, `proc-macro2` 1.0.107, `unicode-ident` 1.0.26. Vet: `quote` is covered by imported Google/Mozilla audits; the other 10 are **tracked exemptions** with notes (`supply-chain/config.toml`), because the importing organisations trust their publishers instead of auditing them (see §8 Q1). The youngest is `unicode-ident` 1.0.26 (11 days).

Spike-only dependencies (own lockfiles under `spikes/`, never in the product graph, removed with the spikes): `rusqlite` =0.40.2 (`libsqlite3-sys` 0.38.2, `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3), `aws-lc-rs` =1.18.1 (`aws-lc-sys` 0.45.0), `slint` =1.18.1. Their product use is governed by ADR-020/027, ADR-023/`06` §3 and ADR-013.

Tools (not Cargo dependencies; pinned in `xtask/src/tools.rs`, ADR-031, each ≥ 7 days old): Rust 1.98.1; nightly-2026-09-21 (rustc 1.100.0-nightly bba531001; Miri, fuzz); cargo-nextest 0.9.145 (0.9.146 was 6 d 21 h old), cargo-deny 0.20.2, cargo-vet 0.10.2, cargo-audit 0.22.2, cargo-auditable 0.7.6, cargo-cyclonedx 0.5.9, cargo-fuzz 0.13.2, cargo-mutants 27.1.0, cargo-llvm-cov 0.9.1, cargo-xwin 0.23.1, cargo-zigbuild 0.23.4, kani-verifier 0.68.0 (with its own nightly-2026-08-21), ProVerif 2.05 (source tarball, SHA-256 from opam), zig 0.16.0; on the macOS host also LLVM 22.1.8 (= rustc's LLVM), CMake 4.4.3, NASM 3.02, opam 2.6.0 / OCaml 5.2.1 (checksums verified against the GitHub release digests / ziglang index; NASM has no published digest, SHA-256 `4c1bbb09…fa114` recorded).

## 7. Open risks and known limitations

1. **Windows release builds vs. SQLCipher (affects M7/M11).** `rusqlite` `bundled-sqlcipher-vendored-openssl` does not cross-build to `x86_64-pc-windows-msvc` with cargo-xwin: OpenSSL's `Configure VC-WIN64A` requires a Windows perl (and `nmake`). `02` §7 plans Windows builds cross-compiled from Linux and `06` §5/§6 plans two Linux builders for reproducibility. With SQLCipher + vendored OpenSSL, Windows release builds must run natively on Windows — or another route is needed (prebuilt OpenSSL for Windows via `OPENSSL_DIR`, the ADR-027 fallback, a different SQLCipher crypto provider). Details in `M0-spikes.md`. Decision needed by M7 at the latest (§8 Q6).
2. **Slint and `#![forbid(unsafe_code)]` (affects M8).** `slint::slint!` expands to `#[allow(unsafe_code)]` and fails under a crate-level `forbid` (E0453); `slint-build` is excluded by the no-build-script rule. `secmp-ui` cannot use Slint's compiled components as the rules stand (§8 Q5).
3. **`unsafe` in the `secmp-sys-*` crates (affects M1).** The workspace sets `unsafe_code = "deny"` for every crate including the two `secmp-sys-*`; their first `unsafe` block (M1: `SecretPage`) needs a lint relaxation (`#![allow(unsafe_code)]` or per-site `#[expect(unsafe_code)]`), which `06` §2's closed list of sanctioned allowances does not contain. The `policy` step will reject it until the list is amended (§8 Q3).
4. **Branch protection is not enforced.** GitHub returns HTTP 403 for branch protection on this private repository on the free plan, so "`main` advances only by reviewed PRs" is a process rule, not a technical one (ADR-029).
5. **CI cost and duration.** The first run builds the pinned tools from source (cache afterwards, keyed per job and branch; caches from a branch are not visible to other branches). `linux-full` now runs on every milestone-branch push and PR (the only way to get `ci-full` evidence before M0 merges, since `schedule` and `workflow_dispatch` need the workflow on `main`). Windows minutes count double on private repositories. Consider trimming triggers after M0.
6. **External availability.** The cooldown check needs `index.crates.io`; ProVerif is built from `proverif.inria.fr` (checksum-verified; not packaged in Debian/Ubuntu); cargo-xwin downloads the MSVC CRT and Windows SDK from Microsoft — which implies accepting Microsoft's license terms for them (prescribed by A1 §4/§5; the owner should be aware). Outages fail the gates closed.
7. **Vacuous inputs in M0.** KATs, fuzz targets, Kani harnesses, ProVerif models, systemd units and the ref/ cross-check have empty expected sets in M0. Each gate still checks its tool (version) and, where possible, runs a self-test (ProVerif true/false fixture, systemd weak-unit fixture); `xtask/src/expect.rs` makes every future shrinkage fail.
8. **Coverage of the binaries is 83.3 %** (5/6 lines each; the stdout-error branch is not exercised). Above the 80 % threshold; noted for completeness.
9. **Local `ci-full` on macOS cannot run `systemd-analyze`** (SKIP, not allowed under `--strict`); the Linux CI run is the authoritative `ci-full`.

## 8. Blocked / questions for the reviewer or owner

Nothing blocks M0 acceptance. Questions (none was decided by the implementer):

- **Q1 (owner/reviewer) — cargo-vet publisher trust.** Mozilla, ISRG and Bytecode Alliance *trust* dtolnay and BurntSushi instead of auditing their crates; `cargo vet suggest` proposes `cargo vet trust`. `06` §3 allows only imported audits or named human audits, so the 10 xtask-only crates are tracked exemptions. Adopt publisher trust for these publishers (recorded in `supply-chain/audits.toml`), or keep the exemptions?
- **Q2 (reviewer) — approve ADR-031 (xtask dependencies) and ADR-032 (release path remapping).**
- **Q3 (reviewer, before M1) — sanctioned `unsafe_code` relaxation for `secmp-sys-*`** (risk 3): amend the `06` §2 list (e.g. `#![allow(unsafe_code)]` at the crate root of exactly those two crates, or per-block `#[expect(unsafe_code)]` with `// SAFETY:`), then list it in `xtask/src/expect.rs`.
- **Q4 (reviewer) — step 14 inputs.** Accept the systemd gate with an empty unit set until M10 (current state), or pull the `05` §4 unit into `deploy/` now?
- **Q5 (reviewer/owner, M8) — Slint vs. `forbid(unsafe_code)`**: `slint-interpreter`, an ADR sanctioning macro-generated `allow(unsafe_code)` in `secmp-ui`, or the egui fallback (ADR-013). Recorded in `M0-spikes.md`.
- **Q6 (owner/reviewer, by M7) — Windows release-build route for SQLCipher** (risk 1), and the resulting ADR-027 status beyond the M0 outcome.
- **Q7 (owner) — branch protection**: upgrade the plan or make the repository public to enforce "PR-only `main`" technically.
- **Q8 (owner) — Dependabot/Renovate.** `06` §3 mentions a Renovate/Dependabot cooldown next to the CI check; M0 implements only the CI check (automated update PRs are an owner choice). Enable Dependabot with `cooldown: default-days: 7`?
- **Q9 (owner) — environment notes.** The remote in Amendment A1 was a placeholder (`<REPO-URL>`); the existing empty private repository `CarlKIGbR/SecMPro` was used. `GH_TOKEN` was not set in this session; pushes and `gh` used the existing `gh` keyring login (no token was written anywhere). No `sudo`/Homebrew on the Mac: host tools live in `~/.local/opt` (symlinks in `~/.local/bin`), Rust in `~/.rustup`/`~/.cargo`; shell profiles were not modified.
- **Q10 (owner) — libvirt VM timing.** Required from M9; useful from M8 (Windows UI walkthrough, WDA-before-first-paint spike). Owner actions are listed in `xtask/README.md`.

## 9. Checklist before requesting review

- [x] All acceptance criteria evidenced above (the libvirt VM gate is deferred by owner decision A1; the Windows gate ran on `windows-latest`)
- [x] `cargo xtask ci` green on a clean checkout (CI checks out fresh: run 36461122501)
- [x] No `#[ignore]`, no lint allowances added for security lints, no disabled gates (0 `allow`/`expect` attributes in the repository; `policy` enforces it)
- [x] Vectors frozen and reviewed (if changed) — n/a in M0
- [x] Docs/CHANGELOG updated
- [x] Threat model and spec untouched (or ADR'd) — `docs/00–07`, `docs/09` untouched; `docs/08` only owner-decided updates and new ADRs
