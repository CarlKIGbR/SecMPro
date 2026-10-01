// SPDX-License-Identifier: AGPL-3.0-or-later
//! The CI driver: `ci-fast` (docs/06 §5 steps 1–5), `ci-full` (steps 1–14) and `step <id>...`.
//!
//! Every step ends as PASS, FAIL, SKIP (not applicable on this host), DELEGATED (explicitly handed to another
//! CI job with `--delegated <id>`) or STUB (a documented M0 stub). All steps run even after a failure so the
//! summary is complete. With `--strict` (always used in CI) a SKIP is a failure, so nothing can be skipped
//! silently.

use std::path::PathBuf;
use std::time::Instant;

use crate::gates;
use crate::meta::Workspace;
use crate::util::{Result, bail, say, warn};

/// How a step ended (failures are `Err`).
pub(crate) enum Outcome {
    Pass(String),
    Skip(String),
    Stub(String),
}

/// Everything a step may need.
pub(crate) struct Ctx {
    pub(crate) root: PathBuf,
    pub(crate) ws: Workspace,
    pub(crate) host: String,
}

type StepFn = fn(&Ctx) -> Result<Outcome>;

struct Step {
    num: &'static str,
    id: &'static str,
    run: StepFn,
}

const FAST: &[Step] = &[
    Step {
        num: "1",
        id: "fmt",
        run: gates::fmt,
    },
    Step {
        num: "2",
        id: "clippy",
        run: gates::clippy,
    },
    // an accident guard against careless edits of the workflows and lint relaxations, not a tamper-proof control; the
    // real control is review (M3 review F23, R-08)
    Step {
        num: "2",
        id: "policy",
        run: gates::policy,
    },
    Step {
        num: "3",
        id: "deny",
        run: gates::deny,
    },
    Step {
        num: "3",
        id: "vet",
        run: gates::vet,
    },
    Step {
        num: "3",
        id: "audit",
        run: gates::audit,
    },
    Step {
        num: "3",
        id: "cooldown",
        run: gates::cooldown,
    },
    Step {
        num: "4",
        id: "nextest",
        run: gates::nextest,
    },
    Step {
        num: "4",
        id: "doctest",
        run: gates::doctest,
    },
    Step {
        num: "4",
        id: "hello",
        run: gates::hello,
    },
    Step {
        num: "5",
        id: "kat",
        run: gates::kat,
    },
];

const FULL_EXTRA: &[Step] = &[
    // docs/07 M3 "encrypt+decrypt of a message < 3 ms" (M3 plan D11), right after the KATs
    Step {
        num: "5",
        id: "perf",
        run: gates::perf,
    },
    Step {
        num: "5",
        id: "ct",
        run: gates::ct,
    },
    Step {
        num: "6",
        id: "fuzz",
        run: gates::fuzz,
    },
    Step {
        num: "7",
        id: "coverage",
        run: gates::coverage,
    },
    Step {
        num: "8",
        id: "mutants",
        run: gates::mutants,
    },
    Step {
        num: "9",
        id: "miri",
        run: gates::miri,
    },
    Step {
        num: "9",
        id: "kani",
        run: gates::kani,
    },
    Step {
        num: "10",
        id: "proverif",
        run: gates::proverif,
    },
    Step {
        num: "11",
        id: "windows-cross",
        run: gates::windows_cross,
    },
    Step {
        num: "11",
        id: "windows-native",
        run: |c| Ok(gates::windows_native(c)),
    },
    Step {
        num: "11",
        id: "linux-target",
        run: gates::linux_target,
    },
    Step {
        num: "12a",
        id: "ref-vectors",
        run: gates::ref_vectors,
    },
    Step {
        num: "12",
        id: "repro",
        run: |c| Ok(gates::repro(c)),
    },
    Step {
        num: "13",
        id: "sbom",
        run: gates::sbom,
    },
    Step {
        num: "14",
        id: "systemd",
        run: gates::systemd,
    },
];

/// Steps outside `ci-full`, run only by `cargo xtask step <id>` (their own workflows: `miri-full.yml`,
/// `fuzz-nightly.yml`).
const ON_DEMAND: &[Step] = &[
    Step {
        num: "9",
        id: "miri-full",
        run: gates::miri_full,
    },
    Step {
        num: "9",
        id: "miri-full-secmp-sys-mem",
        run: |c| gates::miri_full_package(c, "secmp-sys-mem"),
    },
    Step {
        num: "9",
        id: "miri-full-secmp-sys-desktop",
        run: |c| gates::miri_full_package(c, "secmp-sys-desktop"),
    },
    Step {
        num: "9",
        id: "miri-full-secmp-crypto",
        run: |c| gates::miri_full_package(c, "secmp-crypto"),
    },
    Step {
        num: "9",
        id: "miri-full-secmp-proto",
        run: |c| gates::miri_full_package(c, "secmp-proto"),
    },
    Step {
        num: "6",
        id: "fuzz-nightly",
        run: gates::fuzz_nightly,
    },
];

struct Options {
    strict: bool,
    delegated: Vec<String>,
    ids: Vec<String>,
}

fn parse(args: &[String], takes_ids: bool) -> Result<Options> {
    let mut o = Options {
        strict: false,
        delegated: Vec::new(),
        ids: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--strict" => o.strict = true,
            "--delegated" => match it.next() {
                Some(v) => o.delegated.push(v.clone()),
                None => bail!("--delegated needs a step id"),
            },
            s if takes_ids && !s.starts_with('-') => o.ids.push(s.to_owned()),
            other => bail!("unknown argument {other:?}"),
        }
    }
    Ok(o)
}

fn all_steps() -> impl Iterator<Item = &'static Step> {
    FAST.iter().chain(FULL_EXTRA.iter())
}

fn execute(steps: &[&Step], opts: &Options, label: &str) -> Result<()> {
    for d in &opts.delegated {
        if !steps.iter().any(|s| s.id == d) {
            bail!("--delegated {d}: no such step in {label}");
        }
    }
    let ws = Workspace::load()?;
    let ctx = Ctx {
        root: ws.root.clone(),
        ws,
        host: crate::sbom::host_triple()?,
    };
    let mut rows = Vec::new();
    let mut failed = 0_usize;
    let mut skipped = 0_usize;
    for step in steps {
        say(&format!("\n=== [{}] {} ===", step.num, step.id));
        let started = Instant::now();
        let (status, detail) = if opts.delegated.iter().any(|d| d == step.id) {
            (
                "DELEGATED",
                "handed to another CI job with --delegated".to_owned(),
            )
        } else {
            match (step.run)(&ctx) {
                Ok(Outcome::Pass(d)) => ("PASS", d),
                Ok(Outcome::Stub(d)) => ("STUB", d),
                Ok(Outcome::Skip(d)) => {
                    skipped = skipped.saturating_add(1);
                    if opts.strict {
                        ("FAIL", format!("skipped under --strict: {d}"))
                    } else {
                        ("SKIP", d)
                    }
                }
                Err(e) => ("FAIL", e.to_string()),
            }
        };
        if status == "FAIL" {
            failed = failed.saturating_add(1);
            warn(&format!("FAIL [{}] {}: {detail}", step.num, step.id));
        }
        let secs = started.elapsed().as_secs();
        // ADR-045: the verdict lines as a table in the job summary (stdout locally); informational only
        crate::summary::step_summary(&ctx.root, step.id, status, secs, &detail);
        rows.push((step.num, step.id, status, secs, detail));
    }
    say(&format!(
        "\n=== {label} summary (host {}, strict: {}) ===",
        ctx.host, opts.strict
    ));
    for (num, id, status, secs, detail) in &rows {
        say(&format!(
            "{num:>4} {id:<15} {status:<9} {secs:>5}s  {detail}"
        ));
    }
    if failed > 0 {
        bail!("{label}: {failed} step(s) failed");
    }
    if skipped > 0 {
        say(&format!(
            "{label}: PASS with {skipped} host-specific skip(s) — not allowed with --strict (CI)"
        ));
    } else {
        say(&format!("{label}: PASS"));
    }
    Ok(())
}

/// `cargo xtask ci-fast [--strict]`.
pub(crate) fn fast(args: &[String]) -> Result<()> {
    let opts = parse(args, false)?;
    let steps: Vec<&Step> = FAST.iter().collect();
    execute(&steps, &opts, "ci-fast")
}

/// `cargo xtask ci-full [--strict] [--delegated ID]...` (alias `ci`).
pub(crate) fn full(args: &[String]) -> Result<()> {
    let opts = parse(args, false)?;
    let steps: Vec<&Step> = all_steps().collect();
    execute(&steps, &opts, "ci-full")
}

/// `cargo xtask step [--strict] ID...` — run selected steps (of `ci-full` or on demand) in the given order.
pub(crate) fn step(args: &[String]) -> Result<()> {
    let opts = parse(args, true)?;
    let selectable = || all_steps().chain(ON_DEMAND.iter());
    if opts.ids.is_empty() {
        let ids: Vec<&str> = selectable().map(|s| s.id).collect();
        bail!(
            "usage: cargo xtask step [--strict] ID...; ids: {}",
            ids.join(" ")
        );
    }
    let mut steps = Vec::new();
    for id in &opts.ids {
        match selectable().find(|s| s.id == id) {
            Some(s) => steps.push(s),
            None => bail!("unknown step {id:?}"),
        }
    }
    execute(&steps, &opts, "step")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_ids_are_unique() {
        let mut ids: Vec<&str> = all_steps().chain(ON_DEMAND.iter()).map(|s| s.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    /// M3 review F22 (Q-4): one on-demand `miri-full-<package>` step per package of `MIRI_PACKAGES`.
    #[test]
    fn miri_full_has_one_step_per_package() {
        for p in crate::expect::MIRI_PACKAGES {
            let id = format!("miri-full-{p}");
            assert_eq!(ON_DEMAND.iter().filter(|s| s.id == id).count(), 1, "{id}");
        }
        assert_eq!(
            ON_DEMAND
                .iter()
                .filter(|s| s.id.starts_with("miri-full-"))
                .count(),
            crate::expect::MIRI_PACKAGES.len()
        );
    }

    #[test]
    fn option_parsing() -> Result<()> {
        let o = parse(
            &[
                "--strict".into(),
                "--delegated".into(),
                "windows-native".into(),
            ],
            false,
        )?;
        assert!(o.strict);
        assert_eq!(o.delegated, vec!["windows-native".to_owned()]);
        assert!(parse(&["fmt".into()], false).is_err());
        assert_eq!(parse(&["fmt".into(), "clippy".into()], true)?.ids.len(), 2);
        assert!(parse(&["--delegated".into()], false).is_err());
        Ok(())
    }
}
