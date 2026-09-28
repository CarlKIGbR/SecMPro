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
use crate::util::{Cmd, Error, Result, bail};

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

/// Evaluate ages against the reference time.
pub(crate) fn evaluate(now: i64, published: &[(String, String, i64)]) -> Result<Vec<Violation>> {
    let mut out = Vec::new();
    for (name, version, t) in published {
        let age = now
            .checked_sub(*t)
            .ok_or_else(|| Error("time arithmetic overflow".to_owned()))?;
        if age < MIN_AGE_SECS {
            out.push(Violation {
                name: name.clone(),
                version: version.clone(),
                age_secs: age,
            });
        }
    }
    Ok(out)
}

fn fetch(name: &str) -> Result<(i64, String)> {
    let url = format!("{INDEX}/{}", index_path(name));
    let raw = Cmd::new("curl")
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
        .read()?;
    let (date, body) = split_response(&raw)?;
    Ok((parse_http_date(&date)?, body))
}

/// `cargo xtask cooldown`: check every registry package in `Cargo.lock`.
pub(crate) fn run(root: &Path) -> Result<String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))?;
    let mut registry = Vec::new();
    for p in parse_lock(&lock) {
        match p.source.as_deref() {
            None => {} // workspace member
            Some(s) if CRATES_IO_SOURCES.contains(&s) => registry.push(p),
            Some(s) => bail!(
                "{} {} comes from a non-crates.io source: {s}",
                p.name,
                p.version
            ),
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
    let violations = match now {
        Some(n) => evaluate(n, &published)?,
        None => Vec::new(),
    };
    if !violations.is_empty() {
        let list: Vec<String> = violations
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
        bail!("dependencies younger than 7 days: {}", list.join(", "));
    }
    let youngest = match now {
        Some(n) => published
            .iter()
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
    Ok(format!(
        "{} registry packages, all ≥ 7 days old{youngest}",
        registry.len()
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
        )?;
        assert_eq!(
            v,
            vec![Violation {
                name: "young".into(),
                version: "2".into(),
                age_secs: MIN_AGE_SECS - 1
            }]
        );
        Ok(())
    }
}
