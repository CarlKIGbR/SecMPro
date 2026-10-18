// SPDX-License-Identifier: AGPL-3.0-or-later
//! Documentation checks (TEST-SPEC-M6-C1 D-01…D-03): statements the code relies on that must stay in the documents.
//! Tests only; the module has no run-time code.

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn read(rel: &str) -> Result<String> {
    Ok(std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel),
    )?)
}

/// The part of the operator's certificate command the planning documents fix (OPEN-M6-09, `OPEN-M6.md`).
const OPENSSL_PREFIX: &str = "openssl req -x509 -newkey ed25519";

/// D-01 (DOC-M6-C-1): `docs/05` §5 names the two DER files next to `direct_tls`, §7 gives the `openssl` command.
#[test]
fn relay_ops_documents_direct_tls_files() -> Result<()> {
    let ops = read("docs/05-relay-ops.md")?;
    let section = |n: &str| -> Result<String> {
        let start = ops.find(&format!("\n## {n}. ")).ok_or("section missing")?;
        let rest = ops.get(start.saturating_add(1)..).ok_or("section")?;
        let end = rest.find("\n## ").unwrap_or(rest.len());
        Ok(rest.get(..end).ok_or("section")?.to_owned())
    };
    let s5 = section("5")?;
    let at = s5.find("direct_tls ").ok_or("direct_tls in §5")?;
    let after = s5.get(at..).ok_or("§5")?;
    assert!(after.contains("direct_tls_cert"), "§5: direct_tls_cert");
    assert!(after.contains("direct_tls_key"), "§5: direct_tls_key");
    assert!(s5.contains("DER"), "§5 says DER");
    let s7 = section("7")?;
    assert!(s7.contains(OPENSSL_PREFIX), "§7: the openssl command");
    let decided = read("docs/reviews/M06-planning/OPEN-M6.md")?;
    assert!(
        decided.contains(OPENSSL_PREFIX),
        "the planning source fixes the same command prefix"
    );
    Ok(())
}

/// D-02 (DOC-M6-C-2): the scheduler's module doc states the flush bound of obligation (i).
#[test]
fn run_module_doc_states_the_flush_bound() -> Result<()> {
    let run = read("crates/secmp-client-core/src/scheduler/run.rs")?;
    let doc: String = run
        .lines()
        .take_while(|l| l.starts_with("//!") || l.starts_with("// SPDX") || l.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "FLUSH_WAIT_MS",
        "next_deadline",
        "driver_jitter_ms",
        "WRITE_STALL_MS",
    ] {
        assert!(doc.contains(needle), "module doc names {needle}");
    }
    Ok(())
}

/// The text of every `.rs` file under `crates/` and `xtask/` (no `target/`).
fn all_rust_sources() -> Result<String> {
    fn walk(dir: &Path, out: &mut String) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
        Ok(())
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = String::new();
    walk(&root.join("crates"), &mut out)?;
    walk(&root.join("xtask"), &mut out)?;
    Ok(out)
}

/// The part of `text` from the line that starts with `from` up to the line that starts with `to`.
fn between<'a>(text: &'a str, from: &str, to: &str) -> Result<&'a str> {
    let start = text.find(from).ok_or("section start missing")?;
    let rest = text.get(start..).ok_or("section")?;
    let end = rest.find(to).ok_or("section end missing")?;
    Ok(rest.get(..end).ok_or("section")?)
}

/// D-03 (BRIEF M6-C1 item 19): the report's §3 names, for each of the 11 rows of `docs/07` §M6 (six Deliverables, five
/// Acceptance criteria), the tests that evidence it — every backticked test name exists in the tree — or says `OPEN — C2`;
/// §6 lists TOR-10 and X-10 as owner-operated and not run; the header says Phase C1; nothing is left to be determined.
#[test]
fn m06_report_acceptance_rows_are_named() -> Result<()> {
    let report = read("docs/reviews/M06-report.md")?;
    let header: String = report.lines().take(4).collect::<Vec<_>>().join("\n");
    assert!(header.contains("Phase C1"), "the header names Phase C1");
    assert!(
        !report.contains(concat!("<", "TBD")),
        "nothing left undecided"
    );
    let s3 = between(&report, "\n## 3. ", "\n## 4. ")?;
    let rows: Vec<&str> = s3
        .lines()
        .filter(|l| l.starts_with("| M6-D") || l.starts_with("| M6-A"))
        .collect();
    let ids: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.trim_start_matches("| ").split(' ').next())
        .collect();
    assert_eq!(
        ids,
        [
            "M6-D1", "M6-D2", "M6-D3", "M6-D4", "M6-D5", "M6-D6", "M6-A1", "M6-A2", "M6-A3",
            "M6-A4", "M6-A5"
        ],
        "6 deliverables and 5 acceptance criteria of docs/07 §M6"
    );
    let sources = all_rust_sources()?;
    for row in &rows {
        let names: Vec<&str> = row
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|t| {
                t.contains('_')
                    && t.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
            .collect();
        for name in &names {
            let found = sources.contains(&format!("fn {name}("))
                || sources.contains(&format!("fn {name}<"));
            assert!(found, "{row}: test `{name}` is not in the tree");
        }
        assert!(
            !names.is_empty() || row.contains("OPEN — C2"),
            "{row}: neither a test name nor `OPEN — C2`"
        );
        if row.contains("OPEN — C2") {
            assert!(
                row.split("OPEN — C2")
                    .nth(1)
                    .is_some_and(|t| t.contains('(')),
                "{row}: `OPEN — C2` names its rows"
            );
        }
    }
    let s6 = between(&report, "\n## 6. ", "\n## 7. ")?;
    for id in ["TOR-10", "X-10"] {
        assert!(
            s6.lines()
                .any(|l| l.contains(id) && l.contains("owner-operated, not run")),
            "§6 lists {id} as owner-operated, not run"
        );
    }
    Ok(())
}
