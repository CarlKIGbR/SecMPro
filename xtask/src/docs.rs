// SPDX-License-Identifier: AGPL-3.0-or-later
//! Documentation checks (TEST-SPEC-M6-C1 D-01…D-03): statements the code relies on that must stay in the documents.
//! Tests only; the module has no run-time code.

use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A document of the repository with LF line ends (a Windows checkout with `core.autocrlf` has CRLF; ADR-047 Am. 5 (3)).
fn read(rel: &str) -> Result<String> {
    Ok(
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel))?
            .replace("\r\n", "\n"),
    )
}

/// A CRLF checkout of the measurement report is searched like an LF one: the section searches of MR-03 and MR-06 find their
/// headings.
#[test]
fn docs_read_normalises_crlf() -> Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
    std::fs::create_dir_all(&dir)?;
    let fixture =
        "# t\r\n\r\n## CPU\r\n\r\nx\r\n\r\n## Recommendation (ADR-018)\r\n\r\ny\r\n\r\n## Gaps\r\n";
    std::fs::write(dir.join("crlf-fixture.md"), fixture)?;
    let text = read("target/crlf-fixture.md")?;
    assert!(!text.contains('\r'));
    assert!(text.contains("\n## CPU\n"));
    assert!(
        text.split("\n## Recommendation (ADR-018)\n")
            .nth(1)
            .is_some()
    );
    Ok(())
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

/// The `## ` headings the measurement report has, in order (MR-03).
const M6_TRAFFIC_SECTIONS: [&str; 8] = [
    "Method",
    "Bandwidth",
    "Tor overhead",
    "Latency over Tor",
    "CPU",
    "Drain 1 h / 24 h",
    "Recommendation (ADR-018)",
    "Gaps",
];

/// Whether `s` contains a date `YYYY-MM-DD`.
fn has_date(s: &str) -> bool {
    s.as_bytes().windows(10).any(|w| {
        w.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            _ => b.is_ascii_digit(),
        })
    })
}

/// MR-03: the findings of a measurement report — a missing or misplaced section, every line that says `not measured` without
/// the reason and the date (`not measured — <reason>, YYYY-MM-DD`), and every line that marks an owner-operated number (⚙)
/// without saying that it is not measured.
fn traffic_report_findings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let headings: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(str::trim)
        .collect();
    if headings != M6_TRAFFIC_SECTIONS {
        out.push(format!(
            "sections {headings:?}, expected {M6_TRAFFIC_SECTIONS:?}"
        ));
    }
    for (n, line) in text.lines().enumerate() {
        let n = n.saturating_add(1);
        let says = line.contains("not measured");
        if says && !(line.contains("not measured — ") && has_date(line)) {
            out.push(format!("line {n}: `not measured` without reason and date"));
        }
        if line.contains('⚙') && !says {
            out.push(format!("line {n}: an owner-operated number is present"));
        }
    }
    out
}

/// MR-03 (`docs/07:126`): `docs/measurements/M6-traffic.md` has the eight sections in the order of the row, and every owner-operated
/// number is not measured with a reason and a date. A missing section and a ⚙ value that is not marked are findings.
#[test]
fn m6_traffic_report_sections() -> Result<()> {
    let report = read("docs/measurements/M6-traffic.md")?;
    assert_eq!(traffic_report_findings(&report), Vec::<String>::new());
    // planted: a section is missing
    let no_cpu = report.replace("\n## CPU\n", "\n## Processor\n");
    assert!(
        traffic_report_findings(&no_cpu)
            .iter()
            .any(|f| f.starts_with("sections"))
    );
    // planted: an owner-operated value is invented, or loses its date
    let invented = format!("{report}\n| MR-04 ⚙ | 6.9 % over Tor |\n");
    assert_eq!(traffic_report_findings(&invented).len(), 1);
    let undated = report.replace(
        "not measured — owner-operated, two machines over real Tor, 2026-10-22",
        "not measured — owner-operated",
    );
    assert!(!traffic_report_findings(&undated).is_empty());
    Ok(())
}

/// MR-06 (ADR-018, [O-22]): the Recommendation section has a row for each of `PERIODS`, `T_BALANCED`, `T_LOWBW`, `F`, `F_M`,
/// `P_POOL` with a measured cost and the §10.1 check, and says that ADR-018 stays proposed; ADR-018 itself is not accepted.
#[test]
fn recommendation_names_every_parameter() -> Result<()> {
    let report = read("docs/measurements/M6-traffic.md")?;
    let section = report
        .split("\n## Recommendation (ADR-018)\n")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .ok_or("no Recommendation section")?;
    for parameter in ["PERIODS", "T_BALANCED", "T_LOWBW", "F", "F_M", "P_POOL"] {
        let row = section
            .lines()
            .find(|l| l.starts_with(&format!("| `{parameter}` |")))
            .ok_or_else(|| format!("no row for {parameter}"))?;
        let plain = row.replace("\\|", "/");
        let cells: Vec<&str> = plain.split('|').map(str::trim).collect();
        // | name | value | cost | check | recommendation |
        assert_eq!(cells.len(), 7, "{row}");
        assert!(
            cells.iter().skip(2).take(4).all(|c| !c.is_empty()),
            "{row}: an empty cell"
        );
    }
    assert!(section.contains("Proposed (owner decides after M6)"));
    let adr = read("docs/08-decisions.md")?;
    let adr018 = between(&adr, "### ADR-018 ", "### ADR-019 ")?;
    assert!(adr018.contains("**Status.** Proposed (owner decides after M6)."));
    assert!(!adr018.contains("Accepted"));
    Ok(())
}

/// MR-07 ([O-03], ADR-051): the report gives the cold-bootstrap cost of Arti without `compression` — both numbers
/// (`bootstrap_seconds=`, `bytes_down=`), or `not measured — <reason, date>` — and `tor_smoke` prints the line the number is read
/// from.
#[test]
fn bootstrap_cost_measured() -> Result<()> {
    let report = read("docs/measurements/M6-traffic.md")?;
    let line = report
        .lines()
        .find(|l| l.contains("Cold bootstrap of Arti"))
        .ok_or("no bootstrap line")?;
    let numbers = |key: &str| {
        line.split(key)
            .nth(1)
            .is_some_and(|t| t.starts_with(|c: char| c.is_ascii_digit()))
    };
    assert!(
        (numbers("bootstrap_seconds=") && numbers("bytes_down="))
            || (line.contains("not measured — ") && has_date(line)),
        "{line}"
    );
    let example = read("crates/secmp-testkit/examples/tor_smoke.rs")?;
    assert!(example.contains("MR07 bootstrap_seconds="));
    assert!(example.contains("bytes_down="));
    Ok(())
}
