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
        let start = ops
            .find(&format!("\n## {n}. "))
            .ok_or("section missing")?;
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
