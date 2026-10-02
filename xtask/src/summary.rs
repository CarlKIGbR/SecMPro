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

/// `### title` and a table with the given header row; one row per entry of `rows` (cells escaped like [`table`]).
pub(crate) fn grid(title: &str, headers: &[&str], rows: &[Vec<String>]) -> String {
    let line = |cells: &mut dyn Iterator<Item = String>| -> String {
        let mut s = String::from("|");
        for c in cells {
            s.push(' ');
            s.push_str(&cell(&c));
            s.push_str(" |");
        }
        s.push('\n');
        s
    };
    let mut out = format!("### {}\n\n", cell(title));
    out.push_str(&line(&mut headers.iter().map(|h| (*h).to_owned())));
    out.push_str(&line(&mut headers.iter().map(|_| "---".to_owned())));
    for r in rows {
        out.push_str(&line(&mut r.iter().cloned()));
    }
    out.push('\n');
    out
}

/// One row of the ProVerif results table (ADR-045, WEISUNG M4-5 §4 (d)): a (model file, `formal/CLAIMS.md` ID) with
/// the verdicts ProVerif gave its `RESULT` lines and the expected ones (e.g. "false ×4"), the wall time of the whole
/// file and the first 12 hex digits of the file's SHA-256.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProverifRow {
    pub(crate) file: String,
    pub(crate) id: String,
    pub(crate) verdict: String,
    pub(crate) expected: String,
    pub(crate) wall_s: f64,
    pub(crate) sha12: String,
}

/// The header line of `target/proverif/results.tsv`, written by the `proverif` step and read by [`proverif_markdown`].
pub(crate) const PROVERIF_TSV_HEADER: &str =
    "file\tclaims_id\tverdict\texpected\twall_s\tsha256_12";

/// The results file of the `proverif` step: [`PROVERIF_TSV_HEADER`], then one tab-separated line per row (tabs and line
/// breaks inside a field become spaces).
pub(crate) fn proverif_tsv(rows: &[ProverifRow]) -> String {
    let field = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let mut lines = vec![PROVERIF_TSV_HEADER.to_owned()];
    lines.extend(rows.iter().map(|r| {
        format!(
            "{}\t{}\t{}\t{}\t{:.1}\t{}",
            field(&r.file),
            field(&r.id),
            field(&r.verdict),
            field(&r.expected),
            r.wall_s,
            field(&r.sha12)
        )
    }));
    lines.push(String::new());
    lines.join("\n")
}

/// The ProVerif results table (ADR-045) from `target/proverif/results.tsv`: one row per (file, ID) with verdict,
/// expected verdict, wall time of the file and the short SHA-256.
pub(crate) fn proverif_markdown(tsv: &str) -> Result<String> {
    let mut lines = tsv.lines();
    if lines.next() != Some(PROVERIF_TSV_HEADER) {
        return Err(Error(
            "proverif summary: results.tsv lacks its header line".to_owned(),
        ));
    }
    let mut rows = Vec::new();
    for l in lines.filter(|l| !l.is_empty()) {
        let cells: Vec<&str> = l.split('\t').collect();
        let [file, id, verdict, expected, wall, sha] = cells.as_slice() else {
            return Err(Error(format!("proverif summary: not six fields: {l:?}")));
        };
        rows.push(vec![
            (*file).to_owned(),
            (*id).to_owned(),
            (*verdict).to_owned(),
            (*expected).to_owned(),
            format!("{wall} s"),
            (*sha).to_owned(),
        ]);
    }
    Ok(grid(
        "ProVerif results (per file and CLAIMS ID)",
        &[
            "file",
            "ID",
            "verdict",
            "expected",
            "wall time of the file",
            "sha256",
        ],
        &rows,
    ))
}

/// The ProVerif model files whose SHA-256 the summary and the evidence show: `formal/tr.pv`, `formal/hx.pvl` and
/// every `formal/hx/*.pv` (sorted), as paths relative to `root`; files that do not exist are left out.
pub(crate) fn proverif_model_files(root: &Path) -> Vec<String> {
    let mut files: Vec<String> = ["formal/tr.pv", crate::expect::PROVERIF_HX_LIB]
        .iter()
        .map(|f| (*f).to_owned())
        .collect();
    let mut hx: Vec<String> = std::fs::read_dir(root.join(crate::expect::PROVERIF_HX_DIR))
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "pv"))
                .filter_map(|p| {
                    p.file_name().map(|n| {
                        format!("{}/{}", crate::expect::PROVERIF_HX_DIR, n.to_string_lossy())
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    hx.sort();
    files.extend(hx);
    files.retain(|f| root.join(f).is_file());
    files
}

/// SHA-256 of a file by the host's tool (`sha256sum`, else `shasum -a 256`); `None` if neither is available.
pub(crate) fn file_sha256(path: &Path) -> Option<String> {
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

/// Extra rows of particular steps: `proverif` the results table of the run (`target/proverif/results.tsv`, written by
/// the step) and the SHA-256 of every model file, `ct` the table of the recorded report.
fn extras(root: &Path, step: &str) -> Vec<String> {
    match step {
        "proverif" => {
            let mut out = Vec::new();
            let results = root.join("target").join("proverif").join("results.tsv");
            if let Ok(tsv) = std::fs::read_to_string(&results) {
                match proverif_markdown(&tsv) {
                    Ok(m) => out.push(m),
                    Err(e) => warn(&format!("proverif summary: {e}")),
                }
            }
            let rows: Vec<(String, String)> = proverif_model_files(root)
                .into_iter()
                .filter_map(|m| file_sha256(&root.join(&m)).map(|h| (m, format!("sha256 {h}"))))
                .collect();
            if !rows.is_empty() {
                out.push(table("ProVerif models", &rows));
            }
            out
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

    /// ADR-045, WEISUNG M4-5 §4 (d): the `proverif` step's results file round-trips into the summary table, one row per
    /// (file, ID); a file without its header or with a short line is refused.
    #[test]
    fn the_proverif_table_comes_from_the_results_file() -> Result<()> {
        let rows = vec![
            ProverifRow {
                file: "formal/tr.pv".to_owned(),
                id: "T13".to_owned(),
                verdict: "false ×7".to_owned(),
                expected: "false ×7".to_owned(),
                wall_s: 70.04,
                sha12: "e1c3f488ae3c".to_owned(),
            },
            ProverifRow {
                file: "formal/hx/hClean.pv".to_owned(),
                id: "H1 (i)".to_owned(),
                verdict: "true ×1".to_owned(),
                expected: "true ×1".to_owned(),
                wall_s: 612.0,
                sha12: "0123456789ab".to_owned(),
            },
        ];
        let tsv = proverif_tsv(&rows);
        assert!(tsv.starts_with(PROVERIF_TSV_HEADER));
        assert!(tsv.contains("formal/tr.pv\tT13\tfalse ×7\tfalse ×7\t70.0\te1c3f488ae3c\n"));
        let md = proverif_markdown(&tsv)?;
        assert!(md.starts_with("### ProVerif results"));
        assert!(md.contains("| file | ID | verdict | expected | wall time of the file | sha256 |"));
        assert!(md.contains(
            "| formal/hx/hClean.pv | H1 (i) | true ×1 | true ×1 | 612.0 s | 0123456789ab |"
        ));
        assert_eq!(md.lines().filter(|l| l.starts_with("| ")).count(), 4);
        assert!(proverif_markdown("formal/tr.pv\tT1\n").is_err());
        assert!(proverif_markdown(&format!("{PROVERIF_TSV_HEADER}\nformal/tr.pv\tT1\n")).is_err());
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
