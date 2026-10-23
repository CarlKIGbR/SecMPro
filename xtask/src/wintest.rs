// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask win-test --backend github|selfhosted|libvirt` — run the Windows gate (docs/06 §4 "Platform",
//! Amendment A1 §2, ADR-029).
//!
//! * `github` (M0–M8): the Windows gate on GitHub-hosted `windows-latest` (native MSVC build, clippy, tests, KATs,
//!   hello-world binaries) for the **pushed commit** of the current branch. By default the `windows-native` job of
//!   the `.github/workflows/ci.yml` run for that commit (the pull-request or push run) is used, waiting for the
//!   job if it is still running; `--rerun` re-executes that job; `--dispatch` starts `.github/workflows/ci-dispatch.yml`
//!   with `suite=windows` and reads its `dispatch-windows` job (GitHub only allows this once `ci-dispatch.yml`
//!   exists on the default branch). The required job names live in `ci.yml` only (M2 review C2), so a dispatch never
//!   adds a check run under a required name. The job log is saved under `target/win-test/`; the command fails
//!   unless the job concluded `success`.
//! * `selfhosted` (M6–M8, on demand, ADR-029 Am. 1): dispatch `.github/workflows/win-ondemand.yml` (the owner's Azure
//!   Windows 11 VM as a self-hosted runner) with `--suite hello|win-test|tor-smoke` (default `win-test`) and read its
//!   `win-suite` job. Dispatchable only once the workflow is on the default branch (HTTP 404 before that: the command
//!   prints the `gh workflow run` line and succeeds), and only for the refs with a federated Azure credential
//!   (`main` only); without a `gh` token it prints the line instead of dispatching. Not a required check.
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

/// The on-demand self-hosted Windows runner (`--backend selfhosted`, ADR-029 Am. 1): `win-ondemand.yml`, job `win-suite`.
const SELFHOSTED: Source = Source {
    workflow: "win-ondemand.yml",
    job: "win-suite",
};

/// The suites of `win-ondemand.yml` (its `suite` input); `win-test` is the default of `--backend selfhosted`.
const SUITES: [&str; 3] = ["hello", "win-test", "tor-smoke"];

/// The refs with a federated Azure credential (ADR-029 Am. 1): an OIDC login from any other ref fails.
const FEDERATED_REFS: [&str; 1] = ["main"];

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

/// The arguments of `gh run list` for the runs of `source` on `branch`.
fn run_list_argv(branch: &str, source: Source) -> Vec<String> {
    [
        "run",
        "list",
        "--workflow",
        source.workflow,
        "--branch",
        branch,
        "--limit",
        "30",
        "--json",
        "databaseId,headSha,event",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn runs(branch: &str, source: Source) -> Result<Vec<Run>> {
    let json = Cmd::new("gh").args(run_list_argv(branch, source)).read()?;
    parse_runs(&json)
}

/// As [`runs`], but a workflow that GitHub does not know yet (not on the default branch) has no runs.
fn runs_if_known(branch: &str, source: Source) -> Result<Vec<Run>> {
    let out = Cmd::new("gh")
        .args(run_list_argv(branch, source))
        .capture()?;
    if out.success {
        return parse_runs(&out.stdout);
    }
    if unknown_workflow(&out.stderr) {
        return Ok(Vec::new());
    }
    bail!("gh run list failed: {}", out.stderr.trim())
}

/// `gh run list --workflow <file>` for a workflow that is not on the default branch.
fn unknown_workflow(stderr: &str) -> bool {
    stderr.contains("could not find any workflows") || stderr.contains("HTTP 404")
}

/// The arguments of `gh workflow run` for `source` on `branch` with the input `suite`.
fn dispatch_argv(source: Source, branch: &str, suite: &str) -> Vec<String> {
    [
        "workflow",
        "run",
        source.workflow,
        "--ref",
        branch,
        "-f",
        &format!("suite={suite}"),
    ]
    .map(str::to_owned)
    .to_vec()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Existing,
    Rerun,
    Dispatch,
}

fn wait_for_new_run(branch: &str, sha: &str, newer_than: u64, source: Source) -> Result<u64> {
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        if let Some(r) = runs(branch, source)?
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
    let local = pushed_head(&branch)?;
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
                .args(dispatch_argv(DISPATCH, &branch, "windows"))
                .run()?;
            wait_for_new_run(&branch, &local, before, DISPATCH)?
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

/// What `--backend selfhosted` does (ADR-029 Am. 1), decided before any git or network call.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Run `gh` with these arguments.
    Dispatch(Vec<String>),
    /// Do not dispatch: show the `gh workflow run` line and the reason; the command still succeeds.
    Print(String, String),
}

/// The `gh workflow run` line for the self-hosted runner, as the owner would type it.
fn dispatch_line(branch: &str, suite: &str) -> String {
    format!("gh {}", dispatch_argv(SELFHOSTED, branch, suite).join(" "))
}

/// Dispatch only for a ref with a federated Azure credential and with a `gh` token; otherwise print the line.
fn decide(branch: &str, authed: bool, suite: &str) -> Decision {
    let line = dispatch_line(branch, suite);
    if !FEDERATED_REFS.contains(&branch) {
        return Decision::Print(
            line,
            format!("no federated credential for {branch} (ADR-029 Am. 1)"),
        );
    }
    if !authed {
        return Decision::Print(line, "no gh token".to_owned());
    }
    Decision::Dispatch(dispatch_argv(SELFHOSTED, branch, suite))
}

/// Carry out a decision: a print goes to `out` and the command succeeds; a dispatch is handed to `dispatch` (the
/// `gh` call, its wait and its collection), whose result is the result.
fn execute(
    decision: Decision,
    out: &mut dyn FnMut(&str),
    dispatch: &mut dyn FnMut(Vec<String>) -> Result<()>,
) -> Result<()> {
    match decision {
        Decision::Print(line, reason) => {
            out(&format!("win-test: not dispatched: {reason}"));
            out(&line);
            Ok(())
        }
        Decision::Dispatch(argv) => dispatch(argv),
    }
}

/// A failed `gh workflow run`: HTTP 404 means GitHub does not know the workflow yet (it dispatches only workflows on
/// the default branch, `docs/reviews/M02-report.md:245-246`), which is a print; any other error stays an error.
fn classify_dispatch_error(output: &str, line: &str) -> Result<Decision> {
    if output.contains("HTTP 404") {
        return Ok(Decision::Print(
            line.to_owned(),
            format!(
                "{} is not on the default branch yet (GitHub dispatches only workflows on the default branch, M02-report.md:245-246)",
                SELFHOSTED.workflow
            ),
        ));
    }
    bail!("`gh workflow run` failed: {}", output.trim())
}

/// `gh auth status` succeeds: there is a token to dispatch with.
fn gh_authed() -> bool {
    Cmd::new("gh")
        .args(["auth", "status"])
        .capture()
        .is_ok_and(|c| c.success)
}

/// The pushed-head check of `github`: the tested commit is the one on origin.
fn pushed_head(branch: &str) -> Result<String> {
    let local = git(&["rev-parse", &format!("refs/heads/{branch}")])?;
    let remote = git(&["ls-remote", "origin", &format!("refs/heads/{branch}")])?;
    let remote_sha = remote.split_whitespace().next().unwrap_or_default();
    if remote_sha != local {
        bail!(
            "origin/{branch} is at {remote_sha:?}, local {branch} at {local}: push first so the tested commit is known"
        );
    }
    Ok(local)
}

/// `--backend selfhosted`: dispatch `win-ondemand.yml` and collect its `win-suite` job.
fn selfhosted(branch_arg: Option<&str>, suite: &str) -> Result<()> {
    let branch = match branch_arg {
        Some(b) => b.to_owned(),
        None => git(&["rev-parse", "--abbrev-ref", "HEAD"])?,
    };
    execute(
        decide(&branch, gh_authed(), suite),
        &mut |l| say(l),
        &mut |argv| dispatch_and_collect(&branch, suite, argv),
    )
}

/// The `Dispatch` of `selfhosted`: the pushed-head check, the `gh workflow run`, the wait for the new run and its
/// `win-suite` job. A 404 from the dispatch is a print (see [`classify_dispatch_error`]).
fn dispatch_and_collect(branch: &str, suite: &str, argv: Vec<String>) -> Result<()> {
    let local = pushed_head(branch)?;
    let before = runs_if_known(branch, SELFHOSTED)?
        .iter()
        .map(|r| r.id)
        .max()
        .unwrap_or(0);
    let out = Cmd::new("gh").args(argv).capture()?;
    if !out.success {
        let text = format!("{}{}", out.stdout, out.stderr);
        let print = classify_dispatch_error(&text, &dispatch_line(branch, suite))?;
        return execute(print, &mut |l| say(l), &mut |_| Ok(()));
    }
    let id = wait_for_new_run(branch, &local, before, SELFHOSTED)?;
    collect(id, branch, &local, SELFHOSTED)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Github,
    Selfhosted,
    Libvirt,
}

/// The parsed command line of `win-test`.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    backend: Backend,
    branch: Option<String>,
    mode: Mode,
    /// The suite of `win-ondemand.yml` (`selfhosted` only; default `win-test`).
    suite: String,
}

const USAGE: &str = "usage: cargo xtask win-test --backend github|selfhosted|libvirt [--ref BRANCH] [--rerun | --dispatch] [--suite hello|win-test|tor-smoke]";

/// Pure: no `git`, no `gh`.
fn parse_args(args: &[String]) -> Result<Args> {
    let mut backend = None;
    let mut branch = None;
    let mut mode = None;
    let mut suite = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--backend" => backend = it.next().cloned(),
            "--ref" => branch = it.next().cloned(),
            "--rerun" => mode = Some(Mode::Rerun),
            "--dispatch" => mode = Some(Mode::Dispatch),
            "--suite" => suite = it.next().cloned(),
            other => bail!("unknown argument {other:?}"),
        }
    }
    let backend = match backend.as_deref() {
        Some("github") => Backend::Github,
        Some("selfhosted") => Backend::Selfhosted,
        Some("libvirt") => Backend::Libvirt,
        _ => bail!("{USAGE}"),
    };
    if backend == Backend::Selfhosted && mode.is_some() {
        bail!(
            "--rerun and --dispatch are not with selfhosted: it always dispatches {}",
            SELFHOSTED.workflow
        );
    }
    if backend != Backend::Selfhosted && suite.is_some() {
        bail!("--suite is only with --backend selfhosted");
    }
    let suite = suite.unwrap_or_else(|| "win-test".to_owned());
    if !SUITES.contains(&suite.as_str()) {
        bail!("unknown suite {suite:?}: one of {}", SUITES.join(", "));
    }
    Ok(Args {
        backend,
        branch,
        mode: mode.unwrap_or(Mode::Existing),
        suite,
    })
}

/// `cargo xtask win-test --backend github|selfhosted|libvirt [--ref BRANCH] [--rerun | --dispatch] [--suite S]`.
pub(crate) fn run(args: &[String]) -> Result<()> {
    let a = parse_args(args)?;
    match a.backend {
        Backend::Github => github(a.branch.as_deref(), a.mode),
        Backend::Selfhosted => selfhosted(a.branch.as_deref(), &a.suite),
        Backend::Libvirt => libvirt(),
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

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    /// W-4a: the dispatch arguments of the self-hosted runner.
    #[test]
    fn selfhosted_dispatch_argv() {
        assert_eq!(
            dispatch_argv(SELFHOSTED, "m06-transport", "win-test"),
            strings(&[
                "workflow",
                "run",
                "win-ondemand.yml",
                "--ref",
                "m06-transport",
                "-f",
                "suite=win-test"
            ])
        );
        assert_eq!(
            dispatch_argv(DISPATCH, "main", "windows"),
            strings(&[
                "workflow",
                "run",
                "ci-dispatch.yml",
                "--ref",
                "main",
                "-f",
                "suite=windows"
            ])
        );
    }

    /// W-4b: the run listing follows the workflow of the source (a selfhosted dispatch must not watch `ci-dispatch.yml`).
    #[test]
    fn run_list_argv_follows_the_source() {
        let want = |workflow: &str| {
            strings(&[
                "run",
                "list",
                "--workflow",
                workflow,
                "--branch",
                "main",
                "--limit",
                "30",
                "--json",
                "databaseId,headSha,event",
            ])
        };
        assert_eq!(run_list_argv("main", DISPATCH), want("ci-dispatch.yml"));
        assert_eq!(run_list_argv("main", SELFHOSTED), want("win-ondemand.yml"));
    }

    /// W-4c: the suite is an enum; `--rerun` and `--dispatch` are github-only. The parser is pure (no `gh` call).
    #[test]
    fn selfhosted_rejects_unknown_suite_and_modes() {
        let base = ["--backend", "selfhosted"];
        let with = |extra: &[&str]| parse_args(&strings(&[&base[..], extra].concat()));
        let e = with(&["--suite", "all"])
            .err()
            .map(|e| e.0)
            .unwrap_or_default();
        assert!(
            e.contains("hello") && e.contains("win-test") && e.contains("tor-smoke"),
            "{e}"
        );
        for flag in ["--rerun", "--dispatch"] {
            let e = with(&[flag]).err().map(|e| e.0).unwrap_or_default();
            assert!(e.contains("not with selfhosted"), "{flag}: {e}");
        }
        assert!(parse_args(&strings(&["--backend", "github", "--suite", "hello"])).is_err());
        let ok = with(&[]).ok();
        assert_eq!(ok.as_ref().map(|a| a.suite.as_str()), Some("win-test"));
        let ok = with(&["--suite", "tor-smoke", "--ref", "main"]).ok();
        assert_eq!(ok.as_ref().map(|a| a.suite.as_str()), Some("tor-smoke"));
        assert_eq!(ok.and_then(|a| a.branch), Some("main".to_owned()));
    }

    /// W-4d: the decision is made before any git or network call.
    #[test]
    fn selfhosted_decision() {
        assert_eq!(
            decide("m06-ct-diag", true, "hello"),
            Decision::Print(
                "gh workflow run win-ondemand.yml --ref m06-ct-diag -f suite=hello".to_owned(),
                "no federated credential for m06-ct-diag (ADR-029 Am. 1)".to_owned()
            )
        );
        for authed in [false, true] {
            assert_eq!(
                decide("m06-transport", authed, "win-test"),
                Decision::Print(
                    "gh workflow run win-ondemand.yml --ref m06-transport -f suite=win-test"
                        .to_owned(),
                    "no federated credential for m06-transport (ADR-029 Am. 1)".to_owned()
                )
            );
        }
        assert_eq!(
            decide("main", false, "win-test"),
            Decision::Print(
                "gh workflow run win-ondemand.yml --ref main -f suite=win-test".to_owned(),
                "no gh token".to_owned()
            )
        );
        assert_eq!(
            decide("main", true, "win-test"),
            Decision::Dispatch(dispatch_argv(SELFHOSTED, "main", "win-test"))
        );
        assert_eq!(
            decide("main", true, "hello"),
            Decision::Dispatch(dispatch_argv(SELFHOSTED, "main", "hello"))
        );
    }

    /// W-4e: printing the command never fails; a 404 (workflow not on the default branch) is a print, any other error is
    /// an error.
    #[test]
    fn selfhosted_print_path_never_fails() -> Result<()> {
        let mut said = Vec::new();
        let d = Decision::Print("the line".to_owned(), "the reason".to_owned());
        execute(d, &mut |l| said.push(l.to_owned()), &mut |_| {
            bail!("a print must not dispatch")
        })?;
        assert!(said.iter().any(|l| l.contains("the line")), "{said:?}");
        assert!(said.iter().any(|l| l.contains("the reason")), "{said:?}");
        let argv = strings(&["workflow", "run"]);
        let mut got = None;
        execute(Decision::Dispatch(argv.clone()), &mut |_| {}, &mut |a| {
            got = Some(a);
            Ok(())
        })?;
        assert_eq!(got, Some(argv));
        let line = "gh workflow run win-ondemand.yml --ref main -f suite=hello";
        let not_found = "HTTP 404: Not Found (https://api.github.com/repos/o/r/actions/workflows/win-ondemand.yml/dispatches)";
        let decision = classify_dispatch_error(not_found, line).ok();
        let Some(Decision::Print(l, reason)) = decision else {
            bail!("404 is not a print: {decision:?}")
        };
        assert_eq!(l, line);
        assert!(reason.contains("not on the default branch"), "{reason}");
        assert!(reason.contains("M02-report.md:245-246"), "{reason}");
        assert!(classify_dispatch_error("HTTP 500", line).is_err());
        assert!(unknown_workflow(
            "could not find any workflows named win-ondemand.yml"
        ));
        assert!(!unknown_workflow("HTTP 500"));
        Ok(())
    }

    /// W-4f: the backend is required; the usage names all three; the source of the self-hosted run.
    #[test]
    fn backend_is_required() {
        assert!(run(&[]).is_err());
        assert!(
            run(&["--backend".into(), "libvirt".into()]).is_err(),
            "libvirt is deferred and must not pass"
        );
        assert!(run(&["--backend".into(), "github".into(), "--bogus".into()]).is_err());
        assert!(run(&["--backend".into(), "selfhosted".into(), "--bogus".into()]).is_err());
        let usage = run(&[]).err().map(|e| e.0).unwrap_or_default();
        assert!(usage.contains("github|selfhosted|libvirt"), "{usage}");
        assert_eq!(
            (SELFHOSTED.workflow, SELFHOSTED.job),
            ("win-ondemand.yml", "win-suite")
        );
    }
}
