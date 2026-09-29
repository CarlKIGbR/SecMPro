// SPDX-License-Identifier: AGPL-3.0-or-later
//! `xtask` — SecMPro build, CI, supply-chain and release automation, run as `cargo xtask <command>`.
//!
//! **Responsibility.** The local mirror of the CI pipeline of docs/06 §5 (`ci-fast`, `ci-full`, single
//! `step`s), the repository policy checks (`unsafe_code` attributes, lint allowances, build scripts, SPDX,
//! workflow hygiene, cargo-vet closure), the 7-day dependency cooldown, SBOM generation, the Windows gate
//! (`win-test`), the SecMP vector cross-check (`vectors`) and pinned tool installation. Stubs until their
//! milestone: `repro-check` (M11), `ops-check` (M10).
//!
//! **Allowed dependencies.** `std` and `serde_json` (ADR-031); external programs are invoked as processes
//! (cargo subcommands, `curl`, `gh`, `git`, `proverif`, `systemd-analyze`, `zig`). Never a dependency of a
//! shipped crate.
#![forbid(unsafe_code)]

mod ci;
mod cooldown;
mod expect;
mod gates;
mod meta;
mod policy;
mod sbom;
mod stubs;
mod time;
mod tools;
mod util;
mod vectors;
mod wintest;

use std::path::Path;
use std::process::ExitCode;

use util::{Result, bail, say, warn};

const USAGE: &str = "\
usage: cargo xtask <command> [options]

  ci-fast [--strict]                        docs/06 §5 steps 1–5 (run after every logical unit)
  ci-full [--strict] [--delegated ID]...    steps 1–14 (before a milestone report; nightly in CI)
  ci                                        alias for ci-full
  step [--strict] ID...                     run selected steps (see `cargo xtask step`)
  policy                                    repository policy checks only
  cooldown                                  7-day dependency cooldown only
  sbom                                      CycloneDX SBOMs + cargo-auditable release builds
  win-test --backend github|libvirt         Windows gate (github: windows-latest; libvirt: from M9)
  install-tools [--set NAME] [--nightly]    install the pinned tools (fast | windows | xwin | full | all)
  vectors                                   generate the Rust vectors, compare with vectors/ref, freeze
  repro-check | ops-check                   documented stubs until M11 / M10";

fn run(args: &[String]) -> Result<()> {
    // Every command runs from the workspace root (the parent of this crate's manifest directory).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| util::Error("xtask has no parent directory".to_owned()))?;
    std::env::set_current_dir(root)?;
    let Some((cmd, rest)) = args.split_first() else {
        say(USAGE);
        bail!("no command given");
    };
    match cmd.as_str() {
        "ci-fast" => ci::fast(rest),
        "ci-full" | "ci" => ci::full(rest),
        "step" => ci::step(rest),
        "policy" => ci::step(&[vec!["policy".to_owned()], rest.to_vec()].concat()),
        "cooldown" => ci::step(&[vec!["cooldown".to_owned()], rest.to_vec()].concat()),
        "sbom" => ci::step(&[vec!["sbom".to_owned()], rest.to_vec()].concat()),
        "win-test" => wintest::run(rest),
        "install-tools" => tools::install(rest),
        "vectors" => vectors::run(root),
        "repro-check" => stubs::repro_check(),
        "ops-check" => stubs::ops_check(),
        "help" | "--help" | "-h" => {
            say(USAGE);
            Ok(())
        }
        other => {
            say(USAGE);
            bail!("unknown command {other:?}")
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            warn(&format!("xtask: error: {e}"));
            ExitCode::FAILURE
        }
    }
}
