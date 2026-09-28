// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask win-test --backend github|libvirt` — run the Windows gate (docs/06 §4 "Platform", Amendment A1
//! §2, ADR-029).
//!
//! * `github` (M0–M8): dispatches `.github/workflows/ci.yml` with `suite=windows` for the pushed commit of the
//!   current branch, waits for the `windows-native` job on `windows-latest` (native MSVC build, clippy, tests,
//!   hello-world binaries), saves the full log under `target/win-test/` and fails unless the job succeeded.
//! * `libvirt` (required from M9, deferred by owner decision A1): documented in `xtask/README.md`, not active.

use serde_json::Value;

use crate::util::{Cmd, Error, Result, bail, say};

const WORKFLOW: &str = "ci.yml";
const JOB: &str = "windows-native";

fn git(args: &[&str]) -> Result<String> {
    Ok(Cmd::new("git")
        .args(args.iter().copied())
        .read()?
        .trim()
        .to_owned())
}

fn run_ids(branch: &str) -> Result<Vec<(u64, String)>> {
    let json = Cmd::new("gh")
        .args([
            "run",
            "list",
            "--workflow",
            WORKFLOW,
            "--branch",
            branch,
            "--event",
            "workflow_dispatch",
        ])
        .args(["--limit", "20", "--json", "databaseId,headSha"])
        .read()?;
    let v: Value = serde_json::from_str(&json).map_err(|e| Error(format!("gh run list: {e}")))?;
    Ok(v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    Some((
                        r.get("databaseId")?.as_u64()?,
                        r.get("headSha")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// Conclusion of the named job in `gh run view --json jobs` output.
pub(crate) fn job_conclusion(json: &str, job: &str) -> Result<String> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("gh run view: {e}")))?;
    v.get("jobs")
        .and_then(Value::as_array)
        .and_then(|jobs| {
            jobs.iter()
                .find(|j| j.get("name").and_then(Value::as_str) == Some(job))
        })
        .and_then(|j| j.get("conclusion").and_then(Value::as_str))
        .map(str::to_owned)
        .ok_or_else(|| Error(format!("job {job} not found in the run")))
}

fn github(branch_arg: Option<&str>) -> Result<()> {
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
    let before = run_ids(&branch)?
        .iter()
        .map(|(id, _)| *id)
        .max()
        .unwrap_or(0);
    Cmd::new("gh")
        .args([
            "workflow",
            "run",
            WORKFLOW,
            "--ref",
            &branch,
            "-f",
            "suite=windows",
        ])
        .run()?;
    let mut run_id = None;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Some((id, _)) = run_ids(&branch)?
            .into_iter()
            .find(|(id, sha)| *id > before && *sha == local)
        {
            run_id = Some(id);
            break;
        }
    }
    let Some(id) = run_id else {
        bail!("the dispatched run did not appear within 5 minutes")
    };
    let id_s = id.to_string();
    say(&format!("win-test: run {id} for {branch} @ {local}"));
    let watched = Cmd::new("gh")
        .args(["run", "watch", &id_s, "--exit-status", "--interval", "30"])
        .run();
    let log = Cmd::new("gh")
        .args(["run", "view", &id_s, "--log"])
        .read()?;
    let dir = std::path::Path::new("target").join("win-test");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("run-{id}.log"));
    std::fs::write(&path, &log)?;
    for line in log.lines().filter(|l| l.starts_with(JOB)) {
        if line.contains("hello-world:")
            || line.contains("Summary [")
            || line.contains(" PASS ")
            || line.contains(" FAIL ")
        {
            say(line);
        }
    }
    let jobs = Cmd::new("gh")
        .args(["run", "view", &id_s, "--json", "jobs"])
        .read()?;
    let conclusion = job_conclusion(&jobs, JOB)?;
    say(&format!(
        "win-test: job {JOB} concluded {conclusion}; full log: {}",
        path.display()
    ));
    watched?;
    if conclusion != "success" {
        bail!("{JOB} concluded {conclusion}");
    }
    Ok(())
}

fn libvirt() -> Result<()> {
    say(
        "win-test --backend libvirt: the ephemeral Windows 11 VM runner (libvirt/QEMU on the owner's server).",
    );
    say(
        "Per run: revert the qcow2 overlay to the read-only base image, boot, copy the test binaries in over the",
    );
    say(
        "QEMU guest agent (guest-file-open/-write) or SSH, execute them, collect exit codes and logs, power off and",
    );
    say(
        "discard the overlay. The VM holds no secrets and only runs commits already on protected branches.",
    );
    say("Procedure and configuration: xtask/README.md (section win-test).");
    bail!(
        "the libvirt backend is deferred by owner decision (Amendment A1): GitHub windows-latest is the Windows gate for M0–M8; the VM is required from M9"
    )
}

/// `cargo xtask win-test --backend github|libvirt [--ref BRANCH]`.
pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut backend = None;
    let mut branch = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--backend" => backend = it.next().cloned(),
            "--ref" => branch = it.next().cloned(),
            other => bail!("unknown argument {other:?}"),
        }
    }
    match backend.as_deref() {
        Some("github") => github(branch.as_deref()),
        Some("libvirt") => libvirt(),
        _ => bail!("usage: cargo xtask win-test --backend github|libvirt [--ref BRANCH]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_lookup() -> Result<()> {
        let json = r#"{"jobs":[{"name":"linux-fast","conclusion":"success"},{"name":"windows-native","conclusion":"failure"}]}"#;
        assert_eq!(job_conclusion(json, "windows-native")?, "failure");
        assert!(job_conclusion(json, "nope").is_err());
        Ok(())
    }

    #[test]
    fn backend_is_required() {
        assert!(run(&[]).is_err());
        assert!(
            run(&["--backend".into(), "libvirt".into()]).is_err(),
            "libvirt is deferred and must not pass"
        );
    }
}
