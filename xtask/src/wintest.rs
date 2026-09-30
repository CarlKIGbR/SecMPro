// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask win-test --backend github|libvirt` — run the Windows gate (docs/06 §4 "Platform", Amendment A1
//! §2, ADR-029).
//!
//! * `github` (M0–M8): the Windows gate on GitHub-hosted `windows-latest` (native MSVC build, clippy, tests, KATs,
//!   hello-world binaries) for the **pushed commit** of the current branch. By default the `windows-native` job of
//!   the `.github/workflows/ci.yml` run for that commit (the pull-request or push run) is used, waiting for the
//!   job if it is still running; `--rerun` re-executes that job; `--dispatch` starts `.github/workflows/ci-dispatch.yml`
//!   with `suite=windows` and reads its `dispatch-windows` job (GitHub only allows this once `ci-dispatch.yml`
//!   exists on the default branch). The required job names live in `ci.yml` only (M2 review C2), so a dispatch never
//!   adds a check run under a required name. The job log is saved under `target/win-test/`; the command fails
//!   unless the job concluded `success`.
//! * `libvirt` (required from M9, deferred by owner decision A1): documented in `xtask/README.md`, not active.

use serde_json::Value;

use crate::util::{Cmd, Error, Result, bail, say};

/// Where the Windows gate of a run lives: the workflow file and the job name.
#[derive(Clone, Copy)]
struct Source {
    workflow: &'static str,
    job: &'static str,
}

/// The pull-request/push run: the required check `windows-native`.
const CI: Source = Source {
    workflow: "ci.yml",
    job: "windows-native",
};

/// A dispatched run (`--dispatch`): `ci-dispatch.yml`, whose job names are not required-check names (review C2).
const DISPATCH: Source = Source {
    workflow: "ci-dispatch.yml",
    job: "dispatch-windows",
};

fn git(args: &[&str]) -> Result<String> {
    Ok(Cmd::new("git")
        .args(args.iter().copied())
        .read()?
        .trim()
        .to_owned())
}

/// A workflow run as listed by `gh run list --json databaseId,headSha,event`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Run {
    pub(crate) id: u64,
    pub(crate) head_sha: String,
    pub(crate) event: String,
}

pub(crate) fn parse_runs(json: &str) -> Result<Vec<Run>> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("gh run list: {e}")))?;
    let Some(items) = v.as_array() else {
        bail!("gh run list: expected a JSON array")
    };
    Ok(items
        .iter()
        .filter_map(|r| {
            Some(Run {
                id: r.get("databaseId")?.as_u64()?,
                head_sha: r.get("headSha")?.as_str()?.to_owned(),
                event: r.get("event")?.as_str()?.to_owned(),
            })
        })
        .collect())
}

fn runs(branch: &str, source: Source) -> Result<Vec<Run>> {
    let json = Cmd::new("gh")
        .args([
            "run",
            "list",
            "--workflow",
            source.workflow,
            "--branch",
            branch,
        ])
        .args(["--limit", "30", "--json", "databaseId,headSha,event"])
        .read()?;
    parse_runs(&json)
}

/// State of one job of a run.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Job {
    pub(crate) id: u64,
    pub(crate) status: String,
    pub(crate) conclusion: String,
}

/// The named job in `gh run view --json jobs` output.
pub(crate) fn job(json: &str, name: &str) -> Result<Job> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("gh run view: {e}")))?;
    let j = v
        .get("jobs")
        .and_then(Value::as_array)
        .and_then(|jobs| {
            jobs.iter()
                .find(|j| j.get("name").and_then(Value::as_str) == Some(name))
        })
        .ok_or_else(|| Error(format!("job {name} not found in the run")))?;
    let text = |key: &str| {
        j.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let id = j
        .get("databaseId")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error(format!("job {name}: no id")))?;
    Ok(Job {
        id,
        status: text("status"),
        conclusion: text("conclusion"),
    })
}

fn job_of_run(run: &str, source: Source) -> Result<Job> {
    job(
        &Cmd::new("gh")
            .args(["run", "view", run, "--json", "jobs"])
            .read()?,
        source.job,
    )
}

/// Remove ANSI escape sequences (CSI `ESC [ ... letter`) from a log.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Existing,
    Rerun,
    Dispatch,
}

fn wait_for_new_run(branch: &str, sha: &str, newer_than: u64) -> Result<u64> {
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Some(r) = runs(branch, DISPATCH)?
            .into_iter()
            .find(|r| r.id > newer_than && r.head_sha == sha)
        {
            return Ok(r.id);
        }
    }
    bail!("the dispatched run did not appear within 5 minutes")
}

fn github(branch_arg: Option<&str>, mode: Mode) -> Result<()> {
    let branch = match branch_arg {
        Some(b) => b.to_owned(),
        None => git(&["rev-parse", "--abbrev-ref", "HEAD"])?,
    };
    let local = git(&["rev-parse", &format!("refs/heads/{branch}")])?;
    let remote = git(&["ls-remote", "origin", &format!("refs/heads/{branch}")])?;
    let remote_sha = remote.split_whitespace().next().unwrap_or_default();
    if remote_sha != local {
        bail!(
            "origin/{branch} is at {remote_sha:?}, local {branch} at {local}: push first so the tested commit is known"
        );
    }
    let source = if mode == Mode::Dispatch { DISPATCH } else { CI };
    let listed = runs(&branch, source)?;
    let newest_for_head = listed
        .iter()
        .filter(|r| r.head_sha == local)
        .map(|r| r.id)
        .max();
    let id = match (mode, newest_for_head) {
        (Mode::Dispatch, _) => {
            let before = listed.iter().map(|r| r.id).max().unwrap_or(0);
            Cmd::new("gh")
                .args([
                    "workflow",
                    "run",
                    DISPATCH.workflow,
                    "--ref",
                    &branch,
                    "-f",
                    "suite=windows",
                ])
                .run()?;
            wait_for_new_run(&branch, &local, before)?
        }
        (_, None) => {
            bail!(
                "no {} run exists for {local}; push the branch (or use --dispatch)",
                CI.workflow
            )
        }
        (Mode::Rerun, Some(id)) => {
            // Wait for the run to finish first: GitHub only re-runs jobs of completed runs.
            let _ = Cmd::new("gh")
                .args(["run", "watch", &id.to_string(), "--interval", "30"])
                .run();
            let job_id = job_of_run(&id.to_string(), CI)?.id;
            Cmd::new("gh")
                .args([
                    "run",
                    "rerun",
                    &id.to_string(),
                    "--job",
                    &job_id.to_string(),
                ])
                .run()?;
            std::thread::sleep(std::time::Duration::from_secs(10));
            id
        }
        (Mode::Existing, Some(id)) => id,
    };
    collect(id, &branch, &local, source)
}

/// Wait for the Windows job of run `id`, save its log and fail unless it succeeded.
fn collect(id: u64, branch: &str, local: &str, source: Source) -> Result<()> {
    let Source { workflow, job } = source;
    let id_s = id.to_string();
    say(&format!(
        "win-test: {workflow} run {id} for {branch} @ {local}; waiting for job {job}"
    ));
    // Wait for the job only (not the whole run): the jobs-log API serves a finished job's log at once.
    let mut state = job_of_run(&id_s, source)?;
    for _ in 0..240 {
        if state.status == "completed" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(30));
        state = job_of_run(&id_s, source)?;
    }
    if state.status != "completed" {
        bail!(
            "job {job} did not complete within 2 hours (status {:?})",
            state.status
        );
    }
    let raw = Cmd::new("gh")
        .args(["api", "--allow-escape-sequences"])
        .arg(format!(
            "repos/{{owner}}/{{repo}}/actions/jobs/{}/logs",
            state.id
        ))
        .read()?;
    let log = strip_ansi(&raw);
    let dir = std::path::Path::new("target").join("win-test");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("run-{id}-job-{}.log", state.id));
    std::fs::write(&path, &log)?;
    for line in log.lines() {
        if line.contains("hello-world:")
            || line.contains("Summary [")
            || line.contains("step summary")
            || line.contains("host: ")
            || line.contains(" PASS ")
            || line.contains(" FAIL ")
        {
            say(line);
        }
    }
    say(&format!(
        "win-test: job {job} ({}) of run {id} concluded {:?}; log: {}",
        state.id,
        state.conclusion,
        path.display()
    ));
    if state.conclusion != "success" {
        bail!("{job} concluded {:?}", state.conclusion);
    }
    Ok(())
}

fn libvirt() -> Result<()> {
    say(
        "win-test --backend libvirt: the ephemeral Windows 11 VM runner (libvirt/QEMU on the owner's server).",
    );
    say(
        "Per run: revert the qcow2 overlay to the read-only base image, boot, copy the test archive in over the",
    );
    say(
        "QEMU guest agent (guest-file-open/-write) or SSH, execute it, collect exit codes and logs, power off and",
    );
    say(
        "discard the overlay. The VM holds no secrets and only runs commits already on protected branches.",
    );
    say("Procedure and configuration: xtask/README.md (section win-test).");
    bail!(
        "the libvirt backend is deferred by owner decision (Amendment A1): GitHub windows-latest is the Windows gate \
         for M0–M8; the VM is required from M9"
    )
}

/// `cargo xtask win-test --backend github|libvirt [--ref BRANCH] [--rerun | --dispatch]`.
pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut backend = None;
    let mut branch = None;
    let mut mode = Mode::Existing;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--backend" => backend = it.next().cloned(),
            "--ref" => branch = it.next().cloned(),
            "--rerun" => mode = Mode::Rerun,
            "--dispatch" => mode = Mode::Dispatch,
            other => bail!("unknown argument {other:?}"),
        }
    }
    match backend.as_deref() {
        Some("github") => github(branch.as_deref(), mode),
        Some("libvirt") => libvirt(),
        _ => bail!(
            "usage: cargo xtask win-test --backend github|libvirt [--ref BRANCH] [--rerun | --dispatch]"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_lookup() -> Result<()> {
        let json = r#"{"jobs":[{"name":"linux-fast","databaseId":1,"status":"completed","conclusion":"success"},
                               {"name":"windows-native","databaseId":2,"status":"completed","conclusion":"failure"}]}"#;
        assert_eq!(
            job(json, "windows-native")?,
            Job {
                id: 2,
                status: "completed".into(),
                conclusion: "failure".into()
            }
        );
        assert!(job(json, "nope").is_err());
        Ok(())
    }

    #[test]
    fn ansi_is_stripped() {
        assert_eq!(
            strip_ansi("\u{1b}[1m\u{1b}[92m   Compiling\u{1b}[0m x"),
            "   Compiling x"
        );
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn run_listing() -> Result<()> {
        let json = r#"[{"databaseId":7,"headSha":"abc","event":"push"},{"databaseId":6,"headSha":"def","event":"pull_request"}]"#;
        let r = parse_runs(json)?;
        assert_eq!(
            r.first(),
            Some(&Run {
                id: 7,
                head_sha: "abc".into(),
                event: "push".into()
            })
        );
        assert!(parse_runs("{}").is_err());
        Ok(())
    }

    #[test]
    fn backend_is_required() {
        assert!(run(&[]).is_err());
        assert!(
            run(&["--backend".into(), "libvirt".into()]).is_err(),
            "libvirt is deferred and must not pass"
        );
        assert!(run(&["--backend".into(), "github".into(), "--bogus".into()]).is_err());
    }
}
