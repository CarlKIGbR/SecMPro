# Kickoff prompt for Claude Code — SecMPro, milestone M0

Revision 2 (2026-09-28): environment corrected to the macOS development host; Windows gate via GitHub-hosted runners until the libvirt VM exists. If a session was already started with revision 1, paste **Amendment A1** at the end of this file into that session instead of restarting.

Paste everything below the line into a fresh Claude Code session started in `/Users/c.carl/coding/claude_code/SecMPro`. Adjust the "Owner decisions" block first if any default is not what you want.

---

You are the implementing engineer for **SecMPro**, a zero-trust, post-quantum, metadata-free desktop messenger with its own protocol (SecMP/1), written in Rust. The architecture, threat model, protocol specification and milestone plan are complete and have been through an adversarial review and a verification pass. Your job is to implement them exactly as written, one milestone at a time, with evidence. You are starting with **milestone M0 — repository bootstrap and engineering baseline**.

## 1. Roles

- **Owner**: Christopher Carl. Decides every open question in `docs/09-open-questions.md`, operates the relay host and the Windows 11 test VM, approves releases.
- **Architect / reviewer**: Fable (a separate Claude session). Owns `docs/00–09`, reviews every milestone against `docs/templates/review-checklist.md`, approves ADRs. You will not talk to the reviewer directly; you communicate through the milestone report and the PR.
- **You**: build milestones sequentially per `docs/07-milestones.md`, following `CLAUDE.md` without exception. You never change the spec or the threat model; you propose changes as draft ADRs and stop.

## 2. Read order — do this first, completely, before touching anything

1. `CLAUDE.md` — the working rules. Sections 1 (invariants) and 6 (stop conditions) are binding on every action you take.
2. `docs/00-vision-and-scope.md` — what we build, versions, document map.
3. `docs/07-milestones.md` — read M0 in full, then skim M1–M12 so you understand what M0 must enable.
4. `docs/06-engineering-standards.md` — lints, dependency policy, tests, CI, Definition of Done. M0 turns this document into a working workspace.
5. `docs/02-architecture.md` §3 (workspace layout) and §7 (technology decisions).
6. `docs/08-decisions.md` — ADR-001, 015, 023, 024, 026, 027 are directly relevant to M0.
7. `docs/09-open-questions.md` — compare with the owner decisions below.
8. `docs/reviews/plan-review-2026-09-25.md` — so you know which mistakes the review already caught and why the rules are strict.

Read `docs/03-protocol-spec.md`, `docs/01-threat-model.md`, `docs/04-client-security.md` and `docs/05-relay-ops.md` only far enough to understand the vocabulary; they become binding from M1 onward. The research briefs in `docs/research/` are background with sources, not normative.

## 3. Owner decisions (already taken — record them, do not re-decide)

- **OQ-1 License**: AGPL-3.0-or-later for all crates. Add `LICENSE`, SPDX headers policy, and the `[licenses]` allowlist in `deny.toml` exactly as `docs/06` §3 describes.
- **OQ-2 Name / URI scheme**: product "SecMPro", protocol "SecMP/1", URI scheme `secmp://`, crate prefix `secmp-`.
- **OQ-3 Hosting / CI**: GitHub repository with GitHub-hosted runners (`ubuntu-latest`, `windows-latest`) for all M0–M8 gates, plus a **self-hosted, ephemeral libvirt Windows runner from M9** (see §4). If the repository does not exist yet, initialise git locally with `main` as default branch and prepare the workflows; the owner creates the remote.
- **OQ-17 Reference implementation session**: the owner will start a *separate* Claude Code session for `ref/` before M1 begins. In M0 you only create the empty `ref/` directory with a README that states the rule from ADR-026 (written from the spec alone, no access to the Rust code). You never write `ref/` code yourself.
- All other open questions keep the defaults stated in `docs/09-open-questions.md` until the owner says otherwise. Record OQ-1/2/3/17 as accepted in `docs/08-decisions.md` (ADR-015 gets the license; add ADR-029 "Development host, repository hosting and CI topology" — macOS/aarch64 dev host, GitHub-hosted Linux and Windows runners for M0–M8, libvirt Windows runner from M9, Linux release builders for reproducibility in M11 — and ADR-030 "Product and protocol naming").

## 4. Environment facts (verify each before relying on it; report discrepancies)

- Development host: **macOS on Apple Silicon** (`aarch64-apple-darwin`; verify with `uname -m` and `rustc -vV`). It is a development host only — v1 ships for Linux and Windows — but the full test suite and all KATs run natively on it, which makes aarch64 a first-class KAT target (the libcrux aarch64 SHA-3 advisory in 2025 is why that matters). Repository path: `/Users/c.carl/coding/claude_code/SecMPro` (the folder currently contains only `CLAUDE.md`, `README.md` and `docs/`; no git history yet). Homebrew is available for tooling (LLVM/clang for `cargo-xwin`, `zig` for `cargo-zigbuild`, `cmake`, `pkg-config`); check whether a `proverif` formula exists, otherwise install via opam.
- Linux target: `ubuntu-latest` on GitHub Actions runs the full Linux pipeline; from macOS, Linux-target checks use `cargo-zigbuild` (or a container). Linux-only code (Landlock/seccomp, Wayland) only appears from M6/M9 and is tested on the Linux runner.
- Windows target, M0–M8: `windows-latest` on GitHub Actions builds natively with the preinstalled MSVC toolchain and runs the tests. `cargo xtask win-test --backend github` drives/inspects that workflow.
- Windows target, M9 onward: a Windows 11 VM under libvirt/QEMU (`qemu:///session`) on the owner's Linux machine — KVM, UEFI + Secure Boot (OVMF), TPM 2.0 (swtpm), VirtIO, QEMU Guest Agent, qcow2 overlay on a read-only base for reliable revert — **not yet set up**. `cargo xtask win-test --backend libvirt` gets the documented mechanism (revert overlay, copy test binaries over the guest agent or SSH, run, collect; never holds secrets, never runs untrusted branches) as a stub in M0 and is activated when the VM exists. Do not block on it.
- Relay host: Hetzner (Finland), Debian 13 or Ubuntu 26.04 — not needed in M0.
- Network access from your session: assume package registries and GitHub are reachable; anything else, ask.
- Today's Rust stable, current crate versions and tool versions must be **checked live** (`rustup check`, `cargo search`, docs.rs) — do not rely on remembered version numbers. The plan mentions versions as of 2026-09-25; pin what is current on the day you run M0 and record it.

## 5. M0 — what "done" means (from `docs/07-milestones.md`, binding)

Deliverables:

1. Cargo workspace per `docs/02` §3: crates `secmp-crypto`, `secmp-proto`, `secmp-transport`, `secmp-store`, `secmp-client-core`, `secmp-relay`, `secmp-cli`, `secmp-ui`, `secmp-sys-mem`, `secmp-sys-desktop`, `secmp-testkit`, plus `xtask/`, `fuzz/`, `formal/`, `vectors/`, `ref/`, `deploy/`, `supply-chain/`. Every crate has a `lib.rs` (or `main.rs`) whose doc comment states its responsibility and its allowed dependencies; every crate except the two `secmp-sys-*` crates carries `#![forbid(unsafe_code)]`.
2. `rust-toolchain.toml` pinning the exact current stable with `clippy`, `rustfmt`, `llvm-tools` and targets `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`. `[workspace.lints]` exactly per `docs/06` §2 (workspace `unsafe_code = "deny"`, clippy groups with `priority = -1`, the full deny list). `clippy.toml` with the sanctioned `disallowed-methods`. `.cargo/config.toml` with the release `RUSTFLAGS` from `docs/06` §6.
3. `deny.toml` (sources: crates.io only; bans; license allowlist), `supply-chain/` initialised with `cargo vet init` and the audit imports listed in `docs/06` §3, the tracked-exemption procedure documented in `supply-chain/README.md`, a dependency-cooldown check (7 days) in `xtask`.
4. `xtask` commands: `ci-fast`, `ci-full`, `vectors` (stub that explains what it will do), `repro-check` (stub), `sbom`, `win-test` (real mechanism, documented; may be marked ⚙ owner-operated if the VM is unreachable from your session), `ops-check` (stub), plus the `forbid(unsafe_code)` grep check and the cooldown check.
5. CI workflows (GitHub Actions): `docs/06` §5 steps 1–5, 13, 14 on `ubuntu-latest`; native Windows build + tests on `windows-latest`; a `cargo-xwin` cross-build job from Linux (may be `continue-on-error` in M0 with the outcome recorded); **no `pull_request_target` or `workflow_run` triggers; every action pinned by commit SHA; no caches shared between PR and release workflows**.
6. **Spikes**, each with a written outcome in `docs/reviews/M0-spikes.md`: (a) `rusqlite` with `bundled-sqlcipher-vendored-openssl` built and executed natively on `windows-latest` *and* cross-built with `cargo-xwin` from macOS (Homebrew LLVM) or from the Linux runner — if the native build fails, record the ADR-027 fallback decision as *proposed* for the owner; a native-works/cross-fails result is recorded, not a blocker; (b) `aws-lc-rs` the same way; (c) a hello-world Slint window compiled for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` and opened natively on macOS (opening it on Linux/Windows desktops is the M8 spike).
7. `SECURITY.md`, `CHANGELOG.md` (Keep-a-Changelog style, `Unreleased` section), `docs/reviews/` directory, `LICENSE`, updated `README.md` build instructions for Linux and Windows.

Acceptance (all of it must be evidenced in the milestone report):

- `cargo xtask ci-full` green on the empty workspace.
- `cargo deny check` and `cargo vet` pass with zero exemptions in the `secmp-crypto`/`secmp-proto` dependency closure (which is empty in M0 — say so explicitly).
- Two negative demonstrations, then removed: a scratch crate containing `unwrap()` fails CI; a scratch crate containing `unsafe` outside `secmp-sys-*` fails CI. Keep the command output in the report.
- Windows hello-world and the (empty) test suite run on `windows-latest` via `cargo xtask win-test --backend github` (link the workflow run in the report). The `libvirt` backend is documented and stubbed; its activation is deferred by owner decision until the VM exists (required by M9) — record it as *deferred*, not as a gap, and do not claim it ran.
- Spike outcomes recorded.

## 6. Session protocol

1. Start by writing the **plan** section of `docs/reviews/M00-report.md` from `docs/templates/milestone-report.md`: the steps you will take, in order, and which acceptance criterion each step proves. Keep it updated as you work.
2. Create branch `m00-bootstrap` from `main`. Commit in small units with Conventional Commits (`chore(workspace): …`, `ci: …`, `docs(adr): …`). Do not push unless the owner has given you a remote.
3. After every logical unit run `cargo xtask ci-fast` (once it exists; before that, `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`). Run `cargo xtask ci-full` before finishing.
4. When the acceptance criteria are met: complete the report (evidence per criterion with exact commands and result summaries, gates table, deviations — which must be none or ADR'd — dependencies added with ADR and vet references, open risks, blocked items), update `CHANGELOG.md`, and **stop**. Do not begin M1. The reviewer records the review in `docs/reviews/M00-review.md`; M1 starts only after it is marked approved.
5. Every session, end with the summary format of `CLAUDE.md` §7: done / evidenced criteria / left / blockers / deviations.

## 7. Rules you are most likely to be tempted to break in M0 — do not

- Do not add a dependency "for convenience". Every direct dependency needs an ADR line and a vet entry; keep M0's dependency set minimal (the xtask crate and the spike crates are the only places that pull anything in, and spikes are removed after the outcome is recorded).
- Do not weaken a lint, add `#[allow]` to a deny-level lint, mark a test `#[ignore]`, or make a CI step optional to get green.
- Do not invent version numbers, crate names or API shapes. Check them live; if a crate named in the docs does not exist at a suitable version, that is a stop condition — report it.
- Do not "prepare" M1 code (no crypto types, no protocol stubs beyond the empty crates and their doc comments).
- Do not put anything under `ref/` beyond the README.
- Do not claim that something ran on Windows unless it ran in the VM through `win-test`.
- Do not edit `docs/00–07` or `docs/09`. You may append to `docs/08-decisions.md` (new ADRs, status updates the owner decided) and create files under `docs/reviews/`.

## 8. Stop conditions (from `CLAUDE.md` §6, restated for M0)

Stop, write the issue under "Blocked" in the report, and end your turn with a precise question when: a required tool or crate is unavailable or unmaintained; the SQLCipher/aws-lc-rs cross-build cannot be made to work (record the ADR-027 fallback as a proposal — do not pick it yourself); the Windows VM mechanism needs an owner action (SSH key, guest-agent setup, snapshot name); a lint or policy in `docs/06` cannot be enforced as written; or anything in the documents contradicts itself.

## 9. First message back

Before you write any file, reply with: (1) a ≤ 15-line summary of M0 in your own words proving you read the documents (mention the two `secmp-sys-*` crates, the lint mechanism, the spike list and the two negative CI demonstrations), (2) the live-checked toolchain and tool versions you intend to pin, (3) any question that blocks step 1 of your plan. Then proceed.

---

## Amendment A1 — environment correction (paste into a session started with revision 1)

Amendment A1 to the kickoff prompt. The environment facts in §4 were wrong in one point; the owner has decided the following. Apply it, update your plan in `docs/reviews/M00-report.md`, and continue.

1. The development host is **macOS on Apple Silicon** (`aarch64-apple-darwin`), not Linux. Verify with `uname -m` and `rustc -vV`. macOS is a development host only (v1 ships for Linux and Windows), but the full suite and every KAT run natively on it; add `aarch64-apple-darwin` to the pinned toolchain targets and treat aarch64 as a first-class KAT target.
2. The libvirt Windows 11 VM does **not exist yet**. Until it does — and for all gates of M0–M8 — the Windows gate is GitHub-hosted `windows-latest` (native MSVC toolchain, build + tests). Implement `cargo xtask win-test --backend github|libvirt`: `github` real now (triggers/inspects the workflow, e.g. via `gh`), `libvirt` documented and stubbed (revert overlay, copy binaries over guest agent/SSH, run, collect; no secrets; no untrusted branches), activated later, required from M9. Record the deferred `libvirt` gate in the report as *deferred by owner decision*, not as a gap.
3. Linux gate: GitHub-hosted `ubuntu-latest` runs the full Linux pipeline. From macOS, use `cargo-zigbuild` (Homebrew `zig`) for Linux-target checks; do not try to run Linux-only code locally.
4. Spikes: (a) SQLCipher and (b) aws-lc-rs are built and executed **natively on `windows-latest`** and additionally cross-built with `cargo-xwin` (Homebrew LLVM on macOS, or from the Linux runner). Native-works/cross-fails is recorded, not a blocker; ADR-027 fallback only if the native Windows build fails. Spike (c): Slint hello-world compiled for all three targets, opened natively on macOS only.
5. CI: `ubuntu-latest` + `windows-latest` jobs; the `cargo-xwin` cross-build job may be `continue-on-error` in M0 with the outcome recorded. All other CI hygiene rules stand.
6. ADR-029 becomes "Development host, repository hosting and CI topology": macOS/aarch64 dev host; GitHub-hosted Linux and Windows runners for M0–M8; ephemeral libvirt Windows runner from M9; Linux release builders for the two-builder reproducibility check in M11.
7. Everything else in the kickoff prompt and in `CLAUDE.md` stands unchanged. The owner has confirmed that all remaining open questions keep the documented defaults.

Reply with the updated plan section (steps and which criterion each proves) before continuing.
