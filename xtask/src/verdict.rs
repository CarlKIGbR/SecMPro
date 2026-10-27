// SPDX-License-Identifier: AGPL-3.0-or-later
//! The verdict job `ci-verdict` (ADR-045 Amendment 2, OWNER-M6-02): one required check that is green only if every other
//! gate job of `ci.yml` succeeded. GitHub counts a `skipped` job as passing, and a ruleset that lists many names cannot
//! tell a skipped gate from a passed one; this job reads the `needs` context of the workflow (`NEEDS_JSON`, from
//! `toJSON(needs)`), and a result other than `success` — `skipped`, `cancelled`, `failure` — or a missing job is a failure
//! that names the job.

use serde_json::Value;

use crate::ci::{Ctx, Outcome};
use crate::expect;
use crate::util::{Result, bail, say};

/// The judgement over a `needs` context.
pub(crate) struct Verdict {
    /// One line per job, in the order of `expected` (then any other job of the context).
    pub(crate) lines: Vec<String>,
    /// The failures, each naming its job.
    pub(crate) failures: Vec<String>,
}

/// Judge `needs_json` (the object `toJSON(needs)` gives: job id → `{ "result": …, "outputs": … }`) against the jobs
/// `expected`: every expected job must be there with `result == "success"`; any other job in the context must also have
/// succeeded.
pub(crate) fn judge(needs_json: &str, expected: &[&str]) -> Verdict {
    let mut lines = Vec::new();
    let mut failures = Vec::new();
    let Ok(Value::Object(needs)) = serde_json::from_str::<Value>(needs_json) else {
        failures.push("ci-verdict: NEEDS_JSON is not a JSON object".to_owned());
        return Verdict { lines, failures };
    };
    let result_of = |job: &str| -> Option<String> {
        needs.get(job).map(|v| {
            v.get("result")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        })
    };
    for job in expected {
        match result_of(job) {
            None => failures.push(format!("ci-verdict: {job} missing from needs")),
            Some(result) if result == "success" => lines.push(format!("ci-verdict: {job} success")),
            Some(result) => failures.push(format!(
                "ci-verdict: {job} {}",
                if result.is_empty() {
                    "has no result"
                } else {
                    result.as_str()
                }
            )),
        }
    }
    for job in needs.keys().filter(|k| !expected.contains(&k.as_str())) {
        match result_of(job).as_deref() {
            Some("success") => lines.push(format!("ci-verdict: {job} success (not pinned)")),
            other => failures.push(format!(
                "ci-verdict: {job} {} (not pinned)",
                other.filter(|r| !r.is_empty()).unwrap_or("has no result")
            )),
        }
    }
    Verdict { lines, failures }
}

/// `cargo xtask step --strict ci-verdict`: the verdict over `NEEDS_JSON` and the jobs of
/// [`expect::CI_VERDICT_NEEDS`]; fails unless every one of them succeeded.
pub(crate) fn ci_verdict(_ctx: &Ctx) -> Result<Outcome> {
    let Ok(json) = std::env::var("NEEDS_JSON") else {
        bail!("ci-verdict: NEEDS_JSON is not set (the job passes `toJSON(needs)`)");
    };
    let verdict = judge(&json, expect::CI_VERDICT_NEEDS);
    for l in &verdict.lines {
        say(&format!("  {l}"));
    }
    if !verdict.failures.is_empty() {
        bail!("{}", verdict.failures.join("; "));
    }
    Ok(Outcome::Pass(verdict.lines.join("; ")))
}

#[cfg(test)]
fn needs_with(results: &[(&str, &str)]) -> String {
    let mut m = serde_json::Map::new();
    for (job, result) in results {
        m.insert(
            (*job).to_owned(),
            serde_json::json!({ "result": result, "outputs": {} }),
        );
    }
    Value::Object(m).to_string()
}

#[cfg(test)]
fn all_success() -> Vec<(&'static str, &'static str)> {
    expect::CI_VERDICT_NEEDS
        .iter()
        .map(|j| (*j, "success"))
        .collect()
}

/// V-01: every gate job succeeded: PASS, one line per job.
#[cfg(test)]
#[test]
fn ci_verdict_passes_when_every_gate_succeeded() {
    let v = judge(&needs_with(&all_success()), expect::CI_VERDICT_NEEDS);
    assert!(v.failures.is_empty(), "{:?}", v.failures);
    assert_eq!(v.lines.len(), expect::CI_VERDICT_NEEDS.len());
    for job in expect::CI_VERDICT_NEEDS {
        assert!(
            v.lines
                .iter()
                .any(|l| l == &format!("ci-verdict: {job} success"))
        );
    }
}

/// V-02: a skipped, a cancelled or a failed job is a FAIL that names the job and its result, in every case.
#[cfg(test)]
#[test]
fn ci_verdict_fails_on_skipped_cancelled_or_failed() {
    for (job, result) in [
        ("ct", "skipped"),
        ("kani", "cancelled"),
        ("mutants", "failure"),
    ] {
        let results: Vec<(&str, &str)> = all_success()
            .into_iter()
            .map(|(j, r)| if j == job { (j, result) } else { (j, r) })
            .collect();
        let v = judge(&needs_with(&results), expect::CI_VERDICT_NEEDS);
        assert_eq!(v.failures, vec![format!("ci-verdict: {job} {result}")]);
    }
}

/// V-03: a job missing from the context is a FAIL naming it.
#[cfg(test)]
#[test]
fn ci_verdict_fails_on_a_missing_job() {
    let results: Vec<(&str, &str)> = all_success()
        .into_iter()
        .filter(|(j, _)| *j != "kani")
        .collect();
    let v = judge(&needs_with(&results), expect::CI_VERDICT_NEEDS);
    assert_eq!(
        v.failures,
        vec!["ci-verdict: kani missing from needs".to_owned()]
    );
    // not JSON at all, and a job without a result
    assert!(
        !judge("not json", expect::CI_VERDICT_NEEDS)
            .failures
            .is_empty()
    );
    assert!(!judge("{\"kani\": {}}", &["kani"]).failures.is_empty());
}
