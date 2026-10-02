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
mod ctreport;
mod expect;
mod fuzzseed;
mod gates;
mod meta;
mod policy;
mod sbom;
mod stubs;
mod summary;
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
    ci-full/step: [--models tr|hx|all] [--jobs N]   the proverif step's models (default all) and parallel
                                            processes (default the available cores, at most 4)
  policy                                    repository policy checks only
  cooldown                                  7-day dependency cooldown only
  sbom                                      CycloneDX SBOMs + cargo-auditable release builds
  win-test --backend github|libvirt         Windows gate (github: windows-latest; libvirt: from M9)
  install-tools [--set NAME] [--nightly]    install the pinned tools (fast | windows | xwin | miri | fuzz | full | all)
  vectors                                   generate the Rust vectors, compare with vectors/ref, freeze
  ct-check [--targets current|m2] REPORT... the ct gate's reading of saved ct reports
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
    let (rest, proverif) = split_proverif_options(cmd, rest)?;
    if let Some(o) = proverif {
        gates::set_proverif_options(o)?;
    }
    match cmd.as_str() {
        "ci-fast" => ci::fast(&rest),
        "ci-full" | "ci" => ci::full(&rest),
        "step" => ci::step(&rest),
        "policy" => ci::step(&[vec!["policy".to_owned()], rest].concat()),
        "cooldown" => ci::step(&[vec!["cooldown".to_owned()], rest].concat()),
        "sbom" => ci::step(&[vec!["sbom".to_owned()], rest].concat()),
        "win-test" => wintest::run(&rest),
        "install-tools" => tools::install(&rest),
        "vectors" => vectors::run(root),
        "ct-check" => ctreport::check_files(&rest),
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

/// The options of the `proverif` step (WEISUNG M4-5 §4 (a), gate F7): `--models tr|hx|all` and `--jobs N`, taken out
/// of the arguments of `ci-full`/`ci`/`step` before `ci.rs` parses the rest, and returned apart (`None`: neither
/// given). Other commands keep their arguments unchanged (their parsers refuse both options). With `step`, the options
/// need the `proverif` step among the selected ones; an unknown value, a missing value and an option given twice are
/// refused.
fn split_proverif_options(
    cmd: &str,
    rest: &[String],
) -> Result<(Vec<String>, Option<gates::ProverifOptions>)> {
    if !matches!(cmd, "ci-full" | "ci" | "step") {
        return Ok((rest.to_vec(), None));
    }
    let mut kept = Vec::new();
    let mut models = None;
    let mut jobs = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--models" => {
                let Some(v) = it.next() else {
                    bail!("--models needs tr, hx or all");
                };
                if models.replace(gates::ProverifModels::parse(v)?).is_some() {
                    bail!("--models given twice");
                }
            }
            "--jobs" => {
                let Some(v) = it.next() else {
                    bail!("--jobs needs a number");
                };
                if jobs.replace(gates::parse_proverif_jobs(v)?).is_some() {
                    bail!("--jobs given twice");
                }
            }
            _ => kept.push(a.clone()),
        }
    }
    if models.is_none() && jobs.is_none() {
        return Ok((kept, None));
    }
    if cmd == "step" && !kept.iter().any(|a| a == "proverif") {
        bail!("--models and --jobs belong to the proverif step, which is not selected");
    }
    Ok((
        kept,
        Some(gates::ProverifOptions {
            models: models.unwrap_or(gates::ProverifModels::All),
            jobs,
        }),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    /// WEISUNG M4-5 §4 (a): `--models` and `--jobs` are taken out of `ci-full`/`step` arguments wherever they stand;
    /// unknown values, missing values, repeated options and options without the `proverif` step are refused; other
    /// commands keep them (and refuse them in their own parser).
    #[test]
    fn proverif_options_come_off_the_command_line() -> Result<()> {
        use gates::{ProverifModels, ProverifOptions};
        let (rest, o) =
            split_proverif_options("step", &args("--strict proverif --models hx --jobs 4"))?;
        assert_eq!(rest, args("--strict proverif"));
        assert_eq!(
            o,
            Some(ProverifOptions {
                models: ProverifModels::Hx,
                jobs: Some(4)
            })
        );
        let line = "--strict --delegated windows-native --delegated windows-cross --models tr";
        let (rest, o) = split_proverif_options("ci-full", &args(line))?;
        assert_eq!(
            rest,
            args("--strict --delegated windows-native --delegated windows-cross")
        );
        assert_eq!(
            o,
            Some(ProverifOptions {
                models: ProverifModels::Tr,
                jobs: None
            })
        );
        let (rest, o) = split_proverif_options("ci", &args("--jobs 1"))?;
        assert!(rest.is_empty());
        assert_eq!(o.map(|o| o.models), Some(ProverifModels::All));
        assert_eq!(
            split_proverif_options("ci-full", &args("--strict"))?,
            (args("--strict"), None)
        );
        for bad in [
            "--models",
            "--models tx",
            "--models TR",
            "--models tr --models hx",
            "--jobs",
            "--jobs 0",
            "--jobs 5",
            "--jobs four",
            "--jobs 2 --jobs 2",
        ] {
            assert!(
                split_proverif_options("ci-full", &args(bad)).is_err(),
                "{bad}"
            );
        }
        assert!(split_proverif_options("step", &args("--strict kani --models hx")).is_err());
        assert_eq!(
            split_proverif_options("ci-fast", &args("--models hx"))?,
            (args("--models hx"), None)
        );
        Ok(())
    }
}
