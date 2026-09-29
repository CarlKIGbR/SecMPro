# Review — M00 Repository bootstrap and engineering baseline

Reviewer: Fable (architect) · Date: 2026-09-28 · PR: `CarlKIGbR/SecMPro#1` (`m00-bootstrap` → `main`), final code state `58dc402`, report commit `5b7f678`
Verdict: **APPROVED — with conditions C1–C3 to be met in the same PR before merge, and follow-ups F1–F4 scheduled for M1.**

The reviewer worked from the checked-out branch on the owner's machine (files, git history, evidence logs), not from the report alone. The reviewer could not query GitHub from the review environment; run ids and job conclusions are taken from the evidence logs in `docs/reviews/M00-evidence/` and must be confirmed by the owner on the PR page (C3).

## A. Scope and acceptance

| Criterion | Evidence checked | Result |
|---|---|---|
| `ci-full` green on the empty workspace | `M00-evidence/ci-final-run-36461122501.log` (Linux, `--strict`: 20 PASS, 2 DELEGATED to green jobs, 2 STUB, 0 SKIP); `ci-full-macos.log` | met |
| `cargo deny` / `cargo vet` pass; zero exemptions in the crypto/proto closure | `deny-vet-local.log`; `supply-chain/config.toml` (10 exemptions, all xtask-only, each with a note naming the pulling crate); crypto/proto closure empty | met |
| Negative demonstrations | commits `1e8bd75`, `bab5320`, removal `58dc402`; `negative-unwrap-*.log`, `negative-unsafe-*.log` — clippy failure for `unwrap()`, rustc `unsafe_code` deny plus policy grep for `unsafe` | met |
| Windows hello-world via `win-test --backend github` | `win-test-github-run-36461122501.log`: 32/32 tests, three banners; libvirt backend documented in `xtask/README.md` and deferred by owner decision (Amendment A1) | met |
| Spike outcomes recorded | `docs/reviews/M0-spikes.md` — thorough, with provenance commits and per-platform tables | met |
| Deliverables D1–D7 | workspace (11 crates, doc comments with responsibility and allowed deps, `forbid` in all but the two sys crates — verified by grep), toolchain pin 1.98.1 + aarch64 target, lints verbatim from `06` §2 incl. `priority = -1`, `clippy.toml`, `.cargo/config.toml`, `deny.toml`, cargo-vet with the five imports, xtask commands, CI workflow, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, `README.md` | met |
| Nothing outside scope | no protocol/crypto code; `ref/` holds only the README; spikes removed | met |
| `docs/00–07`, `09` untouched | SHA-256 of every file identical to the reviewer's delivered copies; `08` differs only by the owner-decided updates and ADR-029–032 | met |

## B. Invariants (CLAUDE.md §1) — as far as M0 exercises them

Dependency discipline: one direct dependency (`serde_json`, exact pin, ADR-031), no git deps, no build scripts (policy check `check_build_scripts` verified in `xtask/src/policy.rs`), 7-day cooldown implemented against the crates.io index with the server `Date` header as reference (fail-closed). Lints: enforced by the workspace and demonstrated negatively. CI hygiene: `permissions: contents: read`, only `pull_request`/`push`/`schedule`/`workflow_dispatch` triggers, every action SHA-pinned, `continue-on-error` only on the M0-scoped `xwin-cross` job. No `#[allow]`/`#[expect]` attributes exist in the repository (grep confirmed). Secrets: no token in any file; `gh` keyring used.

## C. Findings

| # | Sev | File | Finding | Required action |
|---|---|---|---|---|
| C1 | major (condition) | `.github/workflows/ci.yml` L112 | `continue-on-error: true` on `xwin-cross` was allowed for M0 only (Amendment A1 §5). It must not survive into M1, where `aws-lc-rs` enters the graph and the cross-build becomes a real gate (with NASM installed on the runner, per spike (b)). | Remove `continue-on-error` and add the NASM install step in the same PR **or** as the first commit of `m01-crypto` — reviewer accepts either, but it must be in the M1 report's gates table as a hard job. Chosen: first commit of M1 (keeps PR #1 evidence intact). |
| C2 | major (condition) | `docs/06` §2, `xtask/src/expect.rs` | The sanctioned-allowance list has no entry for the `unsafe` relaxation the two `secmp-sys-*` crates need in M1, and no entry for the Slint-generated `allow(unsafe_code)` in `secmp-ui`. Without an amendment the `policy` step blocks M1 by construction. | Reviewer amended `docs/06` §2 (see D-2 and D-3 below). Implementer updates `xtask/src/expect.rs` and the `forbid` grep accordingly in the same PR (see "Follow-up commit"). |
| C3 | minor (condition) | PR #1 | The PR-triggered run `36461845974` was still in progress when the report was written. | Owner confirms all four jobs of the PR run are green before squash-merging. |
| F1 | minor | `xtask/src/policy.rs` | Policy checks (workflow hygiene, build-script ban, SPDX, unsanctioned allowances) have few unit tests; only the `forbid` check was demonstrated negatively. | M1: add fixture-based negative tests for every policy check (a workflow with `pull_request_target`, a crate with `build.rs`, a file with an unsanctioned `#[allow]`, an action without SHA). |
| F2 | minor | `.github/workflows/ci.yml` | `linux-full` runs on every milestone-branch push and every PR (report risk 5). Cost only; evidence value is real. | Keep for M1; revisit after M2 when the fuzz/mutation steps become non-trivial (nightly + PR-to-main may suffice). |
| F3 | minor | `README.md` | Fine for M0; will need the `ref/` session note and the public/private status once OQ-18 is decided. | With the OQ-18 decision. |
| F4 | nit | `docs/reviews/M00-report.md` §6 | Tool versions are listed with reasons for choices (good); the NASM SHA-256 is recorded only in the report. | Move recorded checksums of non-registry tools into `xtask/src/tools.rs` (M1). |

No blocker. No deviation without an ADR: D-1 (path remapping) is ADR-032, approved below; D-2 is an owner decision; D-3 (systemd gate with empty input set) is accepted (see Q4).

## D. Reviewer decisions on the questions of report §8

| Q | Decision |
|---|---|
| Q1 publisher trust | **Approved**: `cargo vet trust` for the publishers **dtolnay** and **BurntSushi**, criteria `safe-to-deploy`, `end = 2027-09-28`, recorded in `supply-chain/audits.toml` with the note "publisher trusted by ≥ 2 imported audit sets (Mozilla, ISRG, Bytecode Alliance); reviewed at every release". The ten tracked exemptions are then removed. Rule added to `docs/06` §3 (ADR-015 update). Trust entries are not exemptions; the zero-exemption rule for the crypto/proto closure stands. |
| Q2 ADR-031 / ADR-032 | **Both approved.** ADR-032 with the addition that `cargo xtask release` (M11) is the *only* sanctioned release path, so the remapping always applies; a plain `cargo build --release` is a developer convenience, not a release. |
| Q3 `unsafe` in `secmp-sys-*` | **Decided (docs/06 §2 amended):** `secmp-sys-mem` and `secmp-sys-desktop` carry `#![allow(unsafe_code)]` at the crate root (the whole crate exists for this purpose), and the workspace adds `clippy::undocumented_unsafe_blocks = "deny"` and `clippy::multiple_unsafe_ops_per_block = "deny"`, so every `unsafe` block must have a `// SAFETY:` comment and do one thing. Both lints only fire where `unsafe` exists, so the other crates are unaffected. |
| Q4 systemd gate | **Accepted as is**: the gate self-tests against the weak fixture and its expected unit set grows at M10. No M10 work is pulled forward. |
| Q5 Slint vs `forbid` | **Decided (ADR-033):** `secmp-ui` uses `#![deny(unsafe_code)]` instead of `forbid`; the only tolerated `allow(unsafe_code)` is the one generated inside `slint!` expansions. The `policy` step verifies that no `unsafe` token and no hand-written `allow(unsafe_code)`/`expect(unsafe_code)` appears in `secmp-ui`'s own source files. Build scripts stay banned (so `slint-build` stays out); `slint-interpreter` may be evaluated in the M8 spike as an alternative; egui remains the fallback. |
| Q6 Windows release route | **Decided (ADR-034):** Windows release artefacts are built **natively on Windows**. The two-builder reproducibility check for Windows uses two independent Windows builders (GitHub `windows-latest` and, from M9, the owner's libvirt VM; until then a second GitHub job with a different runner image/date). Linux artefacts keep the two Linux builders. The `cargo-xwin` cross-build remains a CI compile-compatibility check only (with NASM); it is not a release path. Prebuilt OpenSSL (`OPENSSL_DIR`) is rejected as an unvetted supply-chain input; the ADR-027 fallback is not triggered. `02` §7 and `06` §5/§6 updated. ADR-027 status → Accepted (SQLCipher primary). |
| Q7 branch protection | Owner decision, recorded as **OQ-18** with the reviewer's recommendation: make the repository public now (AGPL project; unlimited Actions minutes for public repos — Windows minutes currently count double —, branch protection, private vulnerability reporting and Dependabot alerts all become available; a "pre-release, do not use" banner in the README). Alternative: GitHub Pro. Until decided, "PR-only `main`" stays a process rule. |
| Q8 Dependabot | **Approved**: enable Dependabot for `cargo` and `github-actions`, weekly, grouped, `cooldown: default-days: 7`; the xtask cooldown check remains the gate (Dependabot is a convenience, not a control). |
| Q9 environment notes | Acknowledged. Correct choice on the placeholder URL and on not writing any token. |
| Q10 VM timing | Owner: useful from M8, required by M9 — the owner plans the VM set-up on the Linux/KVM host accordingly (owner actions in `xtask/README.md`). |

## E. Reviewer amendments to the documents (made by the reviewer, 2026-09-28)

- `docs/06` §2: sanctioned allowances extended (D-2/D-3 above); two clippy lints added to the workspace set.
- `docs/06` §3: publisher-trust rule.
- `docs/06` §5 step 11–12 and §6: Windows native release builds and the two-Windows-builder reproducibility check.
- `docs/02` §7: Windows builds row.
- `docs/08`: ADR-027 → Accepted; ADR-031/032 → Accepted; ADR-015 update (publisher trust); new ADR-033 (secmp-ui unsafe exception for Slint-generated code), ADR-034 (Windows release builds native).
- `docs/09`: OQ-18 (repository visibility / branch protection).
- `docs/prompts/kickoff-ref.md`: the brief for the separate `ref/` session (ADR-026), to be started by the owner before M1's vector cross-check.

## F. Follow-up commit required on `m00-bootstrap` before merge (implementer)

One commit `chore(m0): review follow-ups` containing: (1) the reviewer's document amendments as they now sit in the working tree; (2) `supply-chain/audits.toml` trust entries for dtolnay and BurntSushi (`cargo vet trust`), exemptions removed, `cargo vet` green; (3) `[workspace.lints.clippy]` additions `undocumented_unsafe_blocks = "deny"`, `multiple_unsafe_ops_per_block = "deny"`; (4) `xtask/src/expect.rs` and the policy grep updated for the new sanctioned allowances (`#![allow(unsafe_code)]` at the root of exactly the two sys crates; `#![deny(unsafe_code)]` + no `unsafe` token in `secmp-ui`) — with a negative test each; (5) `.github/dependabot.yml`; (6) `CHANGELOG.md` line. `cargo xtask ci-fast` green; push; the PR's CI green (C3); then squash-merge PR #1.

## G. Verdict

**Approved.** M0 is closed when the follow-up commit is on the PR, the PR run is green, and PR #1 is squash-merged into `main`. M1 (`secmp-crypto`) may then start; its first commit removes `continue-on-error` from `xwin-cross` and adds NASM to that job (C1).

Closed 2026-09-28: PR #1 squash-merged as cd5eeb4; reviewer release on run 36467421878.
