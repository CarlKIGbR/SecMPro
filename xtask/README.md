# xtask — `cargo xtask <command>`

Build, CI, supply-chain and release automation (docs/06 §5). The alias lives in `.cargo/config.toml`
(`xtask = "run --package xtask --locked --"`). `cargo xtask help` lists the commands.

| Command | What it does |
|---|---|
| `ci-fast [--strict]` | docs/06 §5 steps 1–5: `fmt`, `clippy`, `policy`, `deny`, `vet`, `audit`, `cooldown`, `nextest`, `doctest`, `hello`, `kat` |
| `ci-full [--strict] [--delegated ID]…` (`ci`) | steps 1–14: the above plus `perf` (M3: TR encrypt+decrypt < 3 ms), `ct`, `fuzz`, `coverage`, `mutants`, `miri`, `kani`, `proverif`, `windows-cross`, `windows-native`, `linux-target`, `ref-vectors`, `repro`, `sbom`, `systemd` |
| `ci-full`/`step`: `[--models tr\|hx\|all] [--jobs N]` | the `proverif` step's models (default `all`: `formal/tr.pv` and every `formal/hx/*.pv`) and the number of parallel ProVerif processes; refused unless the `proverif` step is selected. CI: `linux-full` runs `--models tr`, the job `proverif-hx` runs `step --strict proverif --models hx --jobs 4` (ADR-046) |
| `ci-full --delegated mutants` | the `mutants` step runs in its own CI job (`cargo xtask step --strict mutants`, ADR-047); `linux-full` passes `--delegated mutants` next to `--delegated windows-native --delegated windows-cross` |
| `step [--strict] ID…` | run selected steps, also the on-demand steps outside `ci-full`: `miri-full` (weekly workflow `miri-full.yml`) and `fuzz-nightly` (the 4 h campaign of the daily workflow `fuzz-nightly.yml`) |
| `policy`, `cooldown`, `sbom` | shortcuts for single steps |
| `win-test --backend github\|libvirt [--rerun\|--dispatch]` | the Windows gate (below) |
| `install-tools [--set fast\|windows\|xwin\|miri\|fuzz\|full\|all] [--nightly]` | install the pinned tools (`src/tools.rs`); `SECMP_TOOLS_ROOT` sets `cargo install --root` |
| `vectors`, `repro-check`, `ops-check` | documented stubs until M1, M11 and M10; they exit non-zero |
| `ct-check [--targets current\|m2] REPORT…` | the `ct` gate's reading of saved ct reports (`target/ct-report.json` or committed evidence): re-derives every verdict and control from the recorded statistics (M2 review C3, F15–F17); fails unless every report passes. `--targets m2` reads the committed M2 reports against the target set they were written with (before ADR-042 added `aa_prime_control`) |

Every step ends as PASS, FAIL, SKIP (not applicable on this host, e.g. `systemd-analyze` on macOS), DELEGATED
(handed to another CI job with `--delegated`) or STUB. All steps run and a summary table is printed. **CI always
passes `--strict`, which turns every SKIP into a failure**, so nothing can be skipped silently. Gates discover
their inputs and fail when the discovered set differs from `src/expect.rs`, so a gate cannot pass vacuously
because its inputs disappeared.

## Policy checks (`policy` step)

* `unsafe_code` (docs/06 §2, `src/expect.rs`: `UNSAFE_ALLOWED`, `UNSAFE_DENY_ONLY`): every target root (lib,
  bin, test, bench, example) declares `#![forbid(unsafe_code)]` in its inner-attribute header, except
  * the library root of `secmp-sys-mem` and `secmp-sys-desktop`, which declares `#![allow(unsafe_code)]` — the
    only relaxation of `unsafe_code` allowed anywhere in first-party code (any other `allow`/`expect`/`warn` of
    `unsafe_code`, a `cfg_attr` form or one on an item is a finding);
  * the roots of `secmp-ui`, which declare `#![deny(unsafe_code)]` (or `forbid`); the crate's own `.rs` files
    must contain neither the token `unsafe` (raw text, comments included) nor any relaxation of `unsafe_code`
    (ADR-033: only `slint!` expansions may carry one);
* every member manifest contains exactly `[lints] workspace = true`;
* no `allow`/`expect`/`warn` lint attribute (also inside `cfg_attr`) unless sanctioned by docs/06 §2
  (`src/expect.rs`: `LINT_ALLOWANCES`, test-file rule);
* no build scripts in workspace crates; SPDX headers on every first-party source file;
* workflows: no `pull_request_target`/`workflow_run`, every action pinned by a full commit SHA,
  `continue-on-error` only in the jobs of `CONTINUE_ON_ERROR_JOBS`, no plain-scalar `run:` value containing `: `
  or ` #` (invalid YAML that GitHub rejects without running any job);
* cargo-vet: every exemption carries a tracked-exemption note, and none lies in the `secmp-crypto`/`secmp-proto`
  closure.

## Cooldown (`cooldown` step)

Every registry package in `Cargo.lock` must be at least 7 days old. The publish time is the `pubtime` field of
the crate's crates.io sparse-index file; the reference time is the index server's `Date` header (the local wall
clock is never read). A non-crates.io source, a missing entry or timestamp, or an unreachable index fails the
check. Replaced by Cargo's `global-min-publish-age` once it is stable (docs/06 §3).

## Windows gate: `win-test`

### `--backend github` (M0–M8, Amendment A1 §2)

1. Requires `gh` (authenticated) and that `origin/<branch>` equals the local branch head, so the tested commit
   is known.
2. Selects the run for exactly that commit: by default the `ci.yml` run of the push or pull request (waiting
   while it is in progress); `--rerun` re-executes that run's `windows-native` job; `--dispatch` starts a new
   `ci-dispatch.yml` run with `suite=windows` and reads its `dispatch-windows` job (GitHub accepts dispatches only
   for workflows that exist on the default branch). The required job names exist only in `ci.yml`, which has no
   dispatch trigger (M2 review C2).
3. Waits for the run (`gh run watch`), saves the job log (`windows-native` or `dispatch-windows`) to
   `target/win-test/run-<run>-job-<job>.log`, prints the hello-world banners and the step summary, and fails
   unless the job concluded `success`.

Job `windows-native` runs on GitHub-hosted `windows-latest` with the native MSVC toolchain:
`cargo xtask step --strict clippy nextest doctest kat hello` (clippy with `-D warnings`, all tests, the KATs,
and every workspace binary started once).

### `--backend libvirt` (required from M9; deferred by owner decision A1)

Not active; `cargo xtask win-test --backend libvirt` prints this design and exits non-zero. The mechanism, for
the owner's KVM host:

* **VM**: Windows 11 under libvirt/QEMU (`qemu:///session`), UEFI + Secure Boot (OVMF), TPM 2.0 (swtpm),
  VirtIO, QEMU Guest Agent, and the pinned `cargo-nextest.exe` in the base image. The base image is read-only
  (`chmod 0444`); every run boots a fresh qcow2 overlay.
* **Runner**: a self-hosted GitHub Actions runner on the KVM host, registered with `--ephemeral` and a
  dedicated label (e.g. `secmp-winvm`). The job runs only for `push` to `main`, `schedule` and owner-triggered
  `workflow_dispatch` — never for pull requests — so the VM never runs code from untrusted branches. The VM
  holds no secrets (no tokens, keys or credentials; test binaries only).
* **Per run**:
  1. Build the tests on the host: `cargo nextest archive --target x86_64-pc-windows-msvc
     --archive-file target/win-test/tests.tar.zst` (cross-built with cargo-xwin).
  2. `virsh destroy <domain>` if running; `qemu-img create -f qcow2 -F qcow2 -b <base> <overlay>` (revert).
  3. `virsh start <domain>`; wait for `guest-ping` via `virsh qemu-agent-command`.
  4. Copy the archive and a run script into `C:\secmp-test\` via the guest agent (`guest-file-open`/`-write`/
     `-close`, base64 chunks) or via SSH (key-only, pinned host key) — configurable.
  5. Execute with `guest-exec` (`capture-output: true`): `cargo-nextest.exe nextest run --archive-file …
     --workspace-remap C:\secmp-test\src`; poll `guest-exec-status`; collect exit code, stdout, stderr.
  6. Save everything to `target/win-test/libvirt-<run>.log`; `virsh destroy`; delete the overlay.
* **Configuration** (environment of the runner, set by the owner): `SECMP_WINVM_DOMAIN`, `SECMP_WINVM_BASE`,
  `SECMP_WINVM_OVERLAY`, `SECMP_WINVM_TRANSPORT` (`guest-agent` | `ssh`), `SECMP_WINVM_SSH` (for `ssh`).
* **Owner actions before M9**: build the base image, define the domain, install the guest agent and
  nextest in the image, register the ephemeral runner, set the variables above.
