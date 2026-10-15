// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dependency cooldown (docs/06 §3, CLAUDE.md §1.9): no crate version in `Cargo.lock` may be younger than
//! seven days.
//!
//! Cargo's `global-min-publish-age` is still unstable in the pinned Cargo 1.98.1 (`-Z min-publish-age`), so
//! this check compares every registry package in `Cargo.lock` with the `pubtime` field of its crates.io
//! sparse-index entry. The reference time is the `Date` header of the index response (crates.io's clock; the
//! local wall clock is never read). Anything unexpected — a non-crates.io source, a missing entry or
//! timestamp, an unreachable index — fails the check.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::time::{parse_http_date, parse_rfc3339_utc};
use crate::util::{Cmd, Error, Result, bail, say};

/// Minimum age of every dependency version, in seconds (7 days).
pub(crate) const MIN_AGE_SECS: i64 = 7 * 86_400;

const INDEX: &str = "https://index.crates.io";
const CRATES_IO_SOURCES: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// A `[[package]]` entry of `Cargo.lock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Locked {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
}

fn quoted(line: &str, key: &str) -> Option<String> {
    let rest = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    Some(rest.strip_prefix('"')?.strip_suffix('"')?.to_owned())
}

/// Parse the `[[package]]` entries of a `Cargo.lock` (format version 3 or 4).
pub(crate) fn parse_lock(lock: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut cur: Option<Locked> = None;
    for line in lock.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            if t == "[[package]]" {
                cur = Some(Locked {
                    name: String::new(),
                    version: String::new(),
                    source: None,
                });
            }
            continue;
        }
        if let Some(p) = cur.as_mut() {
            if let Some(v) = quoted(t, "name") {
                p.name = v;
            } else if let Some(v) = quoted(t, "version") {
                p.version = v;
            } else if let Some(v) = quoted(t, "source") {
                p.source = Some(v);
            }
        }
    }
    if let Some(p) = cur {
        out.push(p);
    }
    out
}

/// Path of a crate's file in the sparse index (lower-cased name, 1/2/3/xx/yy layout).
pub(crate) fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    let first: String = n.chars().take(2).collect();
    let second: String = n.chars().skip(2).take(2).collect();
    match n.chars().count() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", n.chars().take(1).collect::<String>()),
        _ => format!("{first}/{second}/{n}"),
    }
}

/// Split a `curl -i` response into (Date header value, body). With redirects or `100 Continue` there can be
/// several header blocks; the last one belongs to the body.
pub(crate) fn split_response(raw: &str) -> Result<(String, String)> {
    let mut rest = raw;
    let mut date = None;
    loop {
        let Some((head, body)) = rest
            .split_once("\r\n\r\n")
            .or_else(|| rest.split_once("\n\n"))
        else {
            bail!("index response has no header/body separator")
        };
        for line in head.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("date")
            {
                date = Some(v.trim().to_owned());
            }
        }
        if body.starts_with("HTTP/") {
            rest = body;
            continue;
        }
        let date = date.ok_or_else(|| Error("index response has no Date header".to_owned()))?;
        return Ok((date, body.to_owned()));
    }
}

/// `pubtime` of `version` in a sparse-index file body (one JSON object per line).
pub(crate) fn pubtime(body: &str, version: &str) -> Result<i64> {
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value =
            serde_json::from_str(line).map_err(|e| Error(format!("bad index line: {e}")))?;
        if v.get("vers").and_then(Value::as_str) == Some(version) {
            let Some(t) = v.get("pubtime").and_then(Value::as_str) else {
                bail!("index entry for version {version} has no pubtime")
            };
            return parse_rfc3339_utc(t);
        }
    }
    bail!("version {version} not found in the index")
}

/// One dependency that violates the cooldown.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) age_secs: i64,
}

/// A cooldown exception (ADR-015 Amendment 2): (crate, version, until `YYYY-MM-DD`, advisory).
pub(crate) type Exception = (&'static str, &'static str, &'static str, &'static str);

/// The result of [`evaluate`]: young packages without a valid exception, the exceptions used (one line each) and the
/// expired exceptions (findings whether or not their package is still young).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) violations: Vec<Violation>,
    pub(crate) used: Vec<String>,
    pub(crate) expired: Vec<String>,
}

/// UTC day number (days since 1970-01-01) of a `YYYY-MM-DD` date.
fn day_of(date: &str) -> Result<i64> {
    let t = parse_rfc3339_utc(&format!("{date}T00:00:00Z"))?;
    Ok(t.div_euclid(86_400))
}

/// Evaluate ages against the reference time. A package younger than 7 days passes iff an exception names its exact
/// (name, version) and the exception's `until` date is not before the UTC date of `now` (ADR-015 Amendment 2); an
/// exception whose `until` date is before that date is itself a finding.
pub(crate) fn evaluate(
    now: i64,
    published: &[(String, String, i64)],
    exceptions: &[Exception],
) -> Result<Evaluation> {
    let today = now.div_euclid(86_400);
    let mut out = Evaluation::default();
    let mut valid = Vec::new();
    for &(name, version, until, advisory) in exceptions {
        if day_of(until)? < today {
            out.expired.push(format!(
                "expired cooldown exception {name}@{version} (until {until})"
            ));
        } else {
            valid.push((name, version, until, advisory));
        }
    }
    for (name, version, t) in published {
        let age = now
            .checked_sub(*t)
            .ok_or_else(|| Error("time arithmetic overflow".to_owned()))?;
        if age < MIN_AGE_SECS {
            if let Some((n, v, until, advisory)) = valid
                .iter()
                .find(|(n, v, _, _)| *n == name.as_str() && *v == version.as_str())
            {
                out.used.push(format!(
                    "cooldown: exception {n}@{v} until {until} ({advisory})"
                ));
            } else {
                out.violations.push(Violation {
                    name: name.clone(),
                    version: version.clone(),
                    age_secs: age,
                });
            }
        }
    }
    Ok(out)
}

/// curl exit codes of a transient transport failure (ADR-015 Amendment 1): DNS (6), connect (7), timeout (28), TLS
/// handshake (35), empty reply (52), receive (56). `--fail` reports every HTTP error as 22, so HTTP 5xx is not told apart
/// and 22 is not transient.
pub(crate) fn is_transient_curl_status(code: Option<i32>) -> bool {
    matches!(code, Some(6 | 7 | 28 | 35 | 52 | 56))
}

/// Attempts per package and the pauses between them, in seconds.
const ATTEMPTS: usize = 3;
const PAUSES_SECS: [u64; 2] = [5, 15];

type Attempt<'a> = &'a mut dyn FnMut(&str) -> std::result::Result<String, (Option<i32>, String)>;

/// The index entry of `name`, fetching with `attempt_fetch` and retrying a transient failure after 5 s and 15 s (at most
/// three attempts); any other failure, and an exhausted retry, is an error. Nothing is ever skipped.
fn fetch_with(
    name: &str,
    attempt_fetch: Attempt<'_>,
    sleep: &mut dyn FnMut(u64),
) -> Result<(i64, String)> {
    let mut attempt = 1_usize;
    loop {
        match attempt_fetch(name) {
            Ok(raw) => {
                let (date, body) = split_response(&raw)?;
                return Ok((parse_http_date(&date)?, body));
            }
            Err((code, msg)) if is_transient_curl_status(code) => {
                if attempt >= ATTEMPTS {
                    bail!("{msg} (after {ATTEMPTS} attempts)");
                }
                say(&format!(
                    "cooldown: retry {}/{ATTEMPTS} for {name} after transient curl exit {}",
                    attempt.saturating_add(1),
                    code.unwrap_or_default()
                ));
                sleep(
                    PAUSES_SECS
                        .get(attempt.saturating_sub(1))
                        .copied()
                        .unwrap_or(15),
                );
                attempt = attempt.saturating_add(1);
            }
            Err((_, msg)) => bail!("{msg}"),
        }
    }
}

fn fetch(name: &str) -> Result<(i64, String)> {
    fetch_with(name, &mut curl_index, &mut |s| {
        std::thread::sleep(std::time::Duration::from_secs(s));
    })
}

fn curl_index(name: &str) -> std::result::Result<String, (Option<i32>, String)> {
    let url = format!("{INDEX}/{}", index_path(name));
    Cmd::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "60",
            "--include",
        ])
        .args([
            "--user-agent",
            "secmpro-xtask-cooldown (https://github.com/CarlKIGbR/SecMPro)",
        ])
        .arg(url)
        .read_with_code()
}

/// The lockfiles checked: the workspace and, when present, the separate cargo-fuzz package.
const LOCKFILES: &[&str] = &["Cargo.lock", "fuzz/Cargo.lock"];

/// `cargo xtask cooldown`: check every registry package in the lockfiles.
pub(crate) fn run(root: &Path) -> Result<String> {
    let mut registry = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut files = Vec::new();
    for rel in LOCKFILES {
        let path = root.join(rel);
        if *rel != "Cargo.lock" && !path.exists() {
            continue;
        }
        files.push(*rel);
        for p in parse_lock(&std::fs::read_to_string(path)?) {
            match p.source.as_deref() {
                None => {} // workspace member
                Some(s) if CRATES_IO_SOURCES.contains(&s) => {
                    if seen.insert((p.name.clone(), p.version.clone())) {
                        registry.push(p);
                    }
                }
                Some(s) => bail!(
                    "{rel}: {} {} comes from a non-crates.io source: {s}",
                    p.name,
                    p.version
                ),
            }
        }
    }
    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    let mut now: Option<i64> = None;
    let mut published = Vec::new();
    for p in &registry {
        if !bodies.contains_key(&p.name) {
            let (date, body) = fetch(&p.name)?;
            now = Some(now.map_or(date, |n| n.max(date)));
            bodies.insert(p.name.clone(), body);
        }
        let body = bodies.get(&p.name).map(String::as_str).unwrap_or_default();
        let t = pubtime(body, &p.version)
            .map_err(|e| Error(format!("{} {}: {e}", p.name, p.version)))?;
        published.push((p.name.clone(), p.version.clone(), t));
    }
    let eval = match now {
        Some(n) => evaluate(n, &published, crate::expect::COOLDOWN_EXCEPTIONS)?,
        None => Evaluation::default(),
    };
    for line in &eval.used {
        say(line);
    }
    let mut findings = eval.expired.clone();
    if !eval.violations.is_empty() {
        let list: Vec<String> = eval
            .violations
            .iter()
            .map(|v| {
                format!(
                    "{} {} (published {} h ago)",
                    v.name,
                    v.version,
                    v.age_secs.checked_div(3_600).unwrap_or(0)
                )
            })
            .collect();
        findings.push(format!(
            "dependencies younger than 7 days: {}",
            list.join(", ")
        ));
    }
    if !findings.is_empty() {
        bail!("{}", findings.join("; "));
    }
    // the youngest package outside the exceptions used (those are listed by name)
    let excepted = |name: &str, v: &str| {
        crate::expect::COOLDOWN_EXCEPTIONS
            .iter()
            .any(|(n, ev, _, _)| *n == name && *ev == v)
    };
    let youngest = match now {
        Some(n) => published
            .iter()
            .filter(|(name, v, _)| !excepted(name, v))
            .filter_map(|(name, v, t)| n.checked_sub(*t).map(|age| (age, name, v)))
            .min()
            .map(|(age, name, v)| {
                format!(
                    "; youngest: {name} {v}, {} days",
                    age.checked_div(86_400).unwrap_or(0)
                )
            })
            .unwrap_or_default(),
        None => String::new(),
    };
    let used = if eval.used.is_empty() {
        String::new()
    } else {
        format!("; {}", eval.used.join("; "))
    };
    Ok(format!(
        "{} registry packages ({}), all ≥ 7 days old or excepted (ADR-015 Am. 2){youngest}{used}",
        registry.len(),
        files.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_parsing() {
        let lock = "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"x\"\n\n[[package]]\nname = \"xtask\"\nversion = \"0.0.0\"\ndependencies = [\n \"a\",\n]\n";
        let p = parse_lock(lock);
        assert_eq!(p.len(), 2);
        assert_eq!(
            p.first().map(|x| (x.name.as_str(), x.version.as_str())),
            Some(("a", "1.0.0"))
        );
        assert_eq!(p.get(1).and_then(|x| x.source.clone()), None);
    }

    #[test]
    fn index_paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("Serde_JSON"), "se/rd/serde_json");
    }

    #[test]
    fn transient_curl_statuses() {
        for c in [6, 7, 28, 35, 52, 56] {
            assert!(is_transient_curl_status(Some(c)), "{c}");
        }
        for c in [0, 1, 3, 22, 23, 60] {
            assert!(!is_transient_curl_status(Some(c)), "{c}");
        }
        assert!(!is_transient_curl_status(None));
    }

    const GOOD: &str = "HTTP/2 200 \r\ncontent-type: text/plain\r\ndate: Mon, 28 Sep 2026 16:10:53 GMT\r\n\r\n{\"name\":\"x\",\"vers\":\"1.0.0\",\"pubtime\":\"2026-09-01T00:00:00Z\"}\n";

    /// Run `fetch_with` over scripted results; returns (result, fetch calls, sleeps).
    fn scripted(
        results: Vec<std::result::Result<String, (Option<i32>, String)>>,
    ) -> (Result<(i64, String)>, usize, Vec<u64>) {
        let mut queue = results.into_iter();
        let mut calls = 0_usize;
        let mut sleeps = Vec::new();
        let out = fetch_with(
            "x",
            &mut |_| {
                calls = calls.saturating_add(1);
                queue
                    .next()
                    .unwrap_or_else(|| Err((None, "exhausted".to_owned())))
            },
            &mut |s| sleeps.push(s),
        );
        (out, calls, sleeps)
    }

    #[test]
    fn transient_failure_is_retried_then_succeeds() {
        let (out, calls, sleeps) = scripted(vec![
            Err((Some(7), "connect".to_owned())),
            Err((Some(7), "connect".to_owned())),
            Ok(GOOD.to_owned()),
        ]);
        assert!(out.is_ok());
        assert_eq!((calls, sleeps), (3, vec![5, 15]));
    }

    #[test]
    fn retry_stops_after_three_transient_failures() {
        let (out, calls, sleeps) = scripted(vec![
            Err((Some(28), "timeout".to_owned())),
            Err((Some(28), "timeout".to_owned())),
            Err((Some(28), "timeout".to_owned())),
        ]);
        let err = out.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("after 3 attempts"), "{err}");
        assert_eq!((calls, sleeps), (3, vec![5, 15]));
    }

    #[test]
    fn non_transient_failure_is_not_retried() {
        let (out, calls, sleeps) = scripted(vec![Err((Some(22), "http".to_owned()))]);
        assert!(out.is_err());
        assert_eq!((calls, sleeps), (1, Vec::new()));
    }

    #[test]
    fn response_split_and_pubtime() -> Result<()> {
        let raw = "HTTP/2 200 \r\ncontent-type: text/plain\r\ndate: Mon, 28 Sep 2026 16:10:53 GMT\r\n\r\n{\"name\":\"x\",\"vers\":\"1.0.0\",\"pubtime\":\"2026-09-01T00:00:00Z\"}\n{\"name\":\"x\",\"vers\":\"1.1.0\"}\n";
        let (date, body) = split_response(raw)?;
        assert_eq!(date, "Mon, 28 Sep 2026 16:10:53 GMT");
        assert_eq!(
            pubtime(&body, "1.0.0")?,
            parse_rfc3339_utc("2026-09-01T00:00:00Z")?
        );
        assert!(
            pubtime(&body, "1.1.0").is_err(),
            "missing pubtime must fail closed"
        );
        assert!(
            pubtime(&body, "9.9.9").is_err(),
            "unknown version must fail closed"
        );
        assert!(
            split_response("HTTP/2 200\r\n\r\nbody").is_err(),
            "missing Date must fail closed"
        );
        Ok(())
    }

    #[test]
    fn seven_day_boundary() -> Result<()> {
        let now = parse_rfc3339_utc("2026-09-28T12:00:00Z")?;
        let ok = parse_rfc3339_utc("2026-09-21T12:00:00Z")?; // exactly 7 days
        let young = parse_rfc3339_utc("2026-09-21T12:00:01Z")?; // one second short
        let v = evaluate(
            now,
            &[
                ("ok".into(), "1".into(), ok),
                ("young".into(), "2".into(), young),
            ],
            &[],
        )?;
        assert_eq!(
            v.violations,
            vec![Violation {
                name: "young".into(),
                version: "2".into(),
                age_secs: MIN_AGE_SECS - 1
            }]
        );
        assert!(v.used.is_empty() && v.expired.is_empty());
        Ok(())
    }

    const EXC: Exception = (
        "rustls",
        "0.23.46",
        "2026-10-21",
        "RUSTSEC-2026-0349 (ADR-015 Am. 2)",
    );

    /// ADR-015 Amendment 2: a young pinned version passes while the exception's `until` date has not passed, also on the
    /// `until` date itself; the gate line names the exception.
    #[test]
    fn exception_allows_young_pinned_version_until_date() -> Result<()> {
        let published = parse_rfc3339_utc("2026-10-14T09:54:00Z")?;
        let pkgs = [("rustls".to_owned(), "0.23.46".to_owned(), published)];
        for now in [
            "2026-10-15T05:00:00Z",
            "2026-10-21T00:00:00Z",
            "2026-10-21T09:53:59Z",
        ] {
            let e = evaluate(parse_rfc3339_utc(now)?, &pkgs, &[EXC])?;
            assert!(e.violations.is_empty(), "{now}: {e:?}");
            assert!(e.expired.is_empty(), "{now}: {e:?}");
            assert_eq!(
                e.used,
                vec!["cooldown: exception rustls@0.23.46 until 2026-10-21 (RUSTSEC-2026-0349 (ADR-015 Am. 2))".to_owned()],
                "{now}"
            );
        }
        // without the exception the same package is a violation
        let e = evaluate(parse_rfc3339_utc("2026-10-15T05:00:00Z")?, &pkgs, &[])?;
        assert_eq!(e.violations.len(), 1);
        Ok(())
    }

    /// An exception past its `until` date is a finding, whether or not its package is still young or still locked.
    #[test]
    fn expired_exception_is_a_finding() -> Result<()> {
        let now = parse_rfc3339_utc("2026-10-22T00:00:00Z")?;
        let old = parse_rfc3339_utc("2026-10-14T09:54:00Z")?; // > 7 days at `now`
        let young = parse_rfc3339_utc("2026-10-20T00:00:00Z")?;
        let expired = "expired cooldown exception rustls@0.23.46 (until 2026-10-21)".to_owned();
        // package no longer young
        let e = evaluate(now, &[("rustls".into(), "0.23.46".into(), old)], &[EXC])?;
        assert_eq!(e.expired, vec![expired.clone()]);
        assert!(e.violations.is_empty() && e.used.is_empty());
        // package not in the lock at all
        let e = evaluate(now, &[], &[EXC])?;
        assert_eq!(e.expired, vec![expired.clone()]);
        // package (hypothetically) still young: expired and not excepted
        let e = evaluate(now, &[("rustls".into(), "0.23.46".into(), young)], &[EXC])?;
        assert_eq!(e.expired, vec![expired]);
        assert_eq!(e.violations.len(), 1);
        assert!(e.used.is_empty());
        Ok(())
    }

    /// The exception covers exactly (name, version): another version of the crate, or another crate, stays a violation.
    #[test]
    fn exception_does_not_cover_other_versions() -> Result<()> {
        let now = parse_rfc3339_utc("2026-10-15T05:00:00Z")?;
        let young = parse_rfc3339_utc("2026-10-14T09:54:00Z")?;
        let e = evaluate(
            now,
            &[
                ("rustls".into(), "0.23.47".into(), young),
                ("rustls-webpki".into(), "0.23.46".into(), young),
                ("rustls".into(), "0.23.46".into(), young),
            ],
            &[EXC],
        )?;
        let names: Vec<(&str, &str)> = e
            .violations
            .iter()
            .map(|v| (v.name.as_str(), v.version.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![("rustls", "0.23.47"), ("rustls-webpki", "0.23.46")]
        );
        assert_eq!(e.used.len(), 1);
        Ok(())
    }
}
