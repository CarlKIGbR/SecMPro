// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gate verdicts as Markdown tables (ADR-045): every xtask gate step appends its verdict lines to the file named by
//! `$GITHUB_STEP_SUMMARY` when that variable is set (so the reviewer reads them on the public run page without a
//! login), and prints the same table to stdout otherwise. The summary is informational: it never changes a step's
//! exit status, and a failure to write it is a warning.

use std::io::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::util::{Error, Result, say, warn};

/// A table cell: pipes and line breaks escaped, so one verdict line stays one row.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// `### title` and a two-column table `item | verdict`; one row per `(item, verdict)`.
pub(crate) fn table(title: &str, rows: &[(String, String)]) -> String {
    let mut out = format!("### {}\n\n| item | verdict |\n|---|---|\n", cell(title));
    for (item, verdict) in rows {
        out.push_str("| ");
        out.push_str(&cell(item));
        out.push_str(" | ");
        out.push_str(&cell(verdict));
        out.push_str(" |\n");
    }
    out.push('\n');
    out
}

/// The verdict lines of a step: its detail split at `; ` (the steps join their findings that way), one row each.
pub(crate) fn step_rows(status: &str, secs: u64, detail: &str) -> Vec<(String, String)> {
    let mut rows = vec![("status".to_owned(), format!("{status} ({secs} s)"))];
    rows.extend(
        detail
            .split("; ")
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, l)| (format!("line {}", i.saturating_add(1)), l.to_owned())),
    );
    rows
}

/// The ct table of a recorded report (ADR-045): the run verdict, the runner timer (clock probe), then one row per
/// verdict line of the gate's own reading (`ctreport::ct_table`: every target with its verdict and largest
/// reproduced shift, k and `q_eff`, and the three controls with Δ, floors and sign).
pub(crate) fn ct_markdown(json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(json).map_err(|e| Error(format!("ct summary: {e}")))?;
    let mut rows = vec![(
        "run verdict".to_owned(),
        v.get("run_verdict")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned(),
    )];
    if let Some(clock) = v.get("clock") {
        rows.push(("runner timer".to_owned(), clock.to_string()));
    }
    let table_view = crate::ctreport::ct_table(json)?;
    for line in &table_view.lines {
        let line = line.trim();
        let (name, rest) = line
            .strip_prefix("ct ")
            .unwrap_or(line)
            .split_once(": ")
            .unwrap_or(("line", line));
        rows.push((name.to_owned(), rest.to_owned()));
    }
    for f in &table_view.failed {
        rows.push(("FINDING".to_owned(), f.clone()));
    }
    Ok(table("constant-time gate (ct)", &rows))
}

/// SHA-256 of a file by the host's tool (`sha256sum`, else `shasum -a 256`); `None` if neither is available.
fn file_sha256(path: &Path) -> Option<String> {
    for (tool, args) in [("sha256sum", &[][..]), ("shasum", &["-a", "256"][..])] {
        if let Ok(out) = std::process::Command::new(tool)
            .args(args)
            .arg(path)
            .output()
            && out.status.success()
        {
            return String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .map(str::to_owned);
        }
    }
    None
}

/// Extra rows of particular steps: `proverif` the SHA-256 of every model, `ct` the table of the recorded report.
fn extras(root: &Path, step: &str) -> Vec<String> {
    match step {
        "proverif" => {
            let rows: Vec<(String, String)> = ["formal/tr.pv", "formal/hx.pv"]
                .iter()
                .filter_map(|m| {
                    let p = root.join(m);
                    file_sha256(&p).map(|h| ((*m).to_owned(), format!("sha256 {h}")))
                })
                .collect();
            if rows.is_empty() {
                Vec::new()
            } else {
                vec![table("ProVerif models", &rows)]
            }
        }
        "ct" => {
            let report = root.join("target").join("ct-report.json");
            match std::fs::read_to_string(&report) {
                Ok(json) => match ct_markdown(&json) {
                    Ok(m) => vec![m],
                    Err(e) => {
                        warn(&format!("ct summary: {e}"));
                        Vec::new()
                    }
                },
                Err(_) => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

/// Write `md` to `$GITHUB_STEP_SUMMARY` (appending) if set, else to stdout.
pub(crate) fn emit(md: &str) {
    match std::env::var_os("GITHUB_STEP_SUMMARY") {
        Some(path) if !path.is_empty() => {
            let written = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|mut f| f.write_all(md.as_bytes()));
            if let Err(e) = written {
                warn(&format!("job summary: {e}"));
            }
        }
        _ => say(md),
    }
}

/// The summary of one finished gate step: its verdict lines, then the extras of the step.
pub(crate) fn step_summary(root: &Path, id: &str, status: &str, secs: u64, detail: &str) {
    emit(&table(
        &format!("gate `{id}`"),
        &step_rows(status, secs, detail),
    ));
    for extra in extras(root, id) {
        emit(&extra);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-045: the summary writer produces the ct table from a recorded report (M3 final run 36840478213): the run
    /// verdict, the runner timer, every target and the three controls.
    #[test]
    fn the_ct_table_comes_from_a_recorded_report() -> Result<()> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/reviews/M03-evidence/ct-report-linux-dispatch-36840478213.json");
        let json = std::fs::read_to_string(&path).map_err(|e| Error(e.to_string()))?;
        let md = ct_markdown(&json)?;
        assert!(md.starts_with("### constant-time gate (ct)"));
        assert!(md.contains("| run verdict | PASS |"));
        assert!(md.contains("| runner timer |"));
        for name in [
            "control_variable_time_compare",
            "tr_decrypt_reject_body_tag",
            "min_leak_control",
            "same_content_control",
            "aa_prime_control",
        ] {
            assert!(md.contains(name), "{name}");
        }
        assert!(md.lines().filter(|l| l.starts_with("| ")).count() >= 18);
        Ok(())
    }

    #[test]
    fn cells_are_escaped_and_rows_follow_the_detail() {
        assert_eq!(cell("a|b\nc"), "a\\|b c");
        let rows = step_rows("PASS", 3, "one; two");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows.first().map(|r| r.1.as_str()), Some("PASS (3 s)"));
        let t = table("t", &rows);
        assert!(t.contains("| line 2 | two |"));
    }
}
