// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay configuration (`docs/05` §5, `/etc/secmp/relay.toml`; OPEN-M5-02, -07, -09 values).
//!
//! A strict subset of TOML, parsed by hand (no serde, no new dependency): `[section]` headers, `key = value` lines,
//! values that are decimal integers (with `_` separators) or double-quoted strings without escapes, `#` comments.
//! Every section and key is known; an unknown or repeated key, a malformed line or a value out of range refuses the
//! start before any listener binds (test RL-23). Absent limits take the OPEN-M5 defaults.
//!
//! ```toml
//! [listen]
//! tor_loopback = "127.0.0.1:7443"
//! [access]
//! key_file = "/run/credentials/secmp-relay.service/relay-keys"
//! [limits]
//! queue_budget_bytes = 6_000_000_000     # OPEN-M5-07: worst-case queue reservations
//! linkdata_budget_bytes = 1_000_000_000  # OPEN-M5-07: link-data reservations
//! link_frames_burst = 8                  # OPEN-M5-02
//! link_frames_per_sec = 1
//! hello_burst = 16
//! hello_per_sec = 4
//! hello_hs1_timeout_secs = 30
//! [shutdown]
//! drain_secs = 60                        # OPEN-M5-09
//! ```

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::budget::BudgetLimits;
use crate::error::{Error, Result};
use crate::rate::RateLimit;

/// The limits a relay runs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The two pools of the memory budget.
    pub budget: BudgetLimits,
    /// The per-link frame rate; `None`: unlimited (the vector replay).
    pub link_rate: Option<RateLimit>,
    /// The per-listener `HELLO` rate; `None`: unlimited.
    pub hello_rate: Option<RateLimit>,
    /// `HELLO` answered → complete `HS1`, in milliseconds (OPEN-M5-02: 30 s).
    pub hello_timeout_ms: u64,
    /// Graceful drain before exit, in seconds (OPEN-M5-09: 60).
    pub drain_secs: u64,
}

/// Default queue pool: 6 GB (`docs/05` §5 `memory_budget_bytes`).
pub const DEFAULT_QUEUE_BUDGET: u64 = 6_000_000_000;
/// Default link-data pool: 1 GB.
pub const DEFAULT_LINKDATA_BUDGET: u64 = 1_000_000_000;
/// Default `HELLO`→`HS1` timeout (OPEN-M5-02).
pub const DEFAULT_HELLO_TIMEOUT_SECS: u64 = 30;
/// Default drain (OPEN-M5-09).
pub const DEFAULT_DRAIN_SECS: u64 = 60;

impl Limits {
    /// The OPEN-M5 defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            budget: BudgetLimits {
                queue_bytes: Some(DEFAULT_QUEUE_BUDGET),
                linkdata_bytes: Some(DEFAULT_LINKDATA_BUDGET),
            },
            link_rate: Some(RateLimit::LINK_DEFAULT),
            hello_rate: Some(RateLimit::HELLO_DEFAULT),
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_SECS.saturating_mul(1000),
            drain_secs: DEFAULT_DRAIN_SECS,
        }
    }

    /// The limits of the `link` vector replay (OPEN-M5-02: limits off; OPEN-M5-07: the vector budget).
    #[must_use]
    pub const fn vectors() -> Self {
        Self {
            budget: BudgetLimits::vectors(),
            link_rate: None,
            hello_rate: None,
            hello_timeout_ms: DEFAULT_HELLO_TIMEOUT_SECS.saturating_mul(1000),
            drain_secs: DEFAULT_DRAIN_SECS,
        }
    }
}

/// A parsed configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The loopback address C tor forwards the onion port to.
    pub listen: SocketAddr,
    /// The key file (`keygen`).
    pub key_file: PathBuf,
    /// The limits.
    pub limits: Limits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Int(u64),
    Str(String),
}

const KEYS: &[(&str, &str)] = &[
    ("listen", "tor_loopback"),
    ("access", "key_file"),
    ("limits", "queue_budget_bytes"),
    ("limits", "linkdata_budget_bytes"),
    ("limits", "link_frames_burst"),
    ("limits", "link_frames_per_sec"),
    ("limits", "hello_burst"),
    ("limits", "hello_per_sec"),
    ("limits", "hello_hs1_timeout_secs"),
    ("shutdown", "drain_secs"),
];

fn parse_value(raw: &str) -> Result<Value> {
    if let Some(inner) = raw.strip_prefix('"') {
        let s = inner
            .strip_suffix('"')
            .ok_or(Error::Config("unterminated string"))?;
        if s.contains('"') || s.contains('\\') {
            return Err(Error::Config("strings take no quotes or escapes"));
        }
        return Ok(Value::Str(s.to_owned()));
    }
    let digits: String = raw.chars().filter(|&c| c != '_').collect();
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || raw.starts_with('_')
        || raw.ends_with('_')
    {
        return Err(Error::Config("a value is neither an integer nor a string"));
    }
    digits
        .parse::<u64>()
        .map(Value::Int)
        .map_err(|_| Error::Config("integer out of range"))
}

/// The text before a `#` that is not inside a string.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return line.get(..i).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn parse_entries(text: &str) -> Result<BTreeMap<(String, String), Value>> {
    let mut section: Option<String> = None;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            let name = name
                .strip_suffix(']')
                .ok_or(Error::Config("malformed section header"))?
                .trim();
            if !KEYS.iter().any(|(s, _)| *s == name) {
                return Err(Error::Config("unknown section"));
            }
            section = Some(name.to_owned());
            continue;
        }
        let (key, raw) = line
            .split_once('=')
            .ok_or(Error::Config("a line is not `key = value`"))?;
        let (key, raw) = (key.trim(), raw.trim());
        let sec = section
            .clone()
            .ok_or(Error::Config("a key outside a section"))?;
        if !KEYS.iter().any(|(s, k)| *s == sec && *k == key) {
            return Err(Error::Config("unknown key"));
        }
        if out
            .insert((sec, key.to_owned()), parse_value(raw)?)
            .is_some()
        {
            return Err(Error::Config("a key is repeated"));
        }
    }
    Ok(out)
}

fn int(entries: &BTreeMap<(String, String), Value>, sec: &str, key: &str) -> Result<Option<u64>> {
    match entries.get(&(sec.to_owned(), key.to_owned())) {
        None => Ok(None),
        Some(Value::Int(v)) => Ok(Some(*v)),
        Some(Value::Str(_)) => Err(Error::Config("an integer key has a string value")),
    }
}

fn string(entries: &BTreeMap<(String, String), Value>, sec: &str, key: &str) -> Result<String> {
    match entries.get(&(sec.to_owned(), key.to_owned())) {
        Some(Value::Str(s)) => Ok(s.clone()),
        Some(Value::Int(_)) => Err(Error::Config("a string key has an integer value")),
        None => Err(Error::Config("a required key is missing")),
    }
}

fn small(v: u64) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::Config("a rate value is out of range"))
}

impl Config {
    /// Parse a configuration text.
    ///
    /// # Errors
    /// [`Error::Config`] naming the broken rule.
    pub fn parse(text: &str) -> Result<Self> {
        let e = parse_entries(text)?;
        let listen: SocketAddr = string(&e, "listen", "tor_loopback")?
            .parse()
            .map_err(|_| Error::Config("tor_loopback is not an address:port"))?;
        if !listen.ip().is_loopback() {
            return Err(Error::Config("tor_loopback must be a loopback address"));
        }
        let key_file = PathBuf::from(string(&e, "access", "key_file")?);
        let d = Limits::defaults();
        let rate = |burst: &str, per: &str, def: Option<RateLimit>| -> Result<Option<RateLimit>> {
            let def = def.unwrap_or(RateLimit {
                burst: 0,
                per_sec: 0,
            });
            Ok(Some(RateLimit {
                burst: int(&e, "limits", burst)?.map_or(Ok(def.burst), small)?,
                per_sec: int(&e, "limits", per)?.map_or(Ok(def.per_sec), small)?,
            }))
        };
        let timeout_secs =
            int(&e, "limits", "hello_hs1_timeout_secs")?.unwrap_or(DEFAULT_HELLO_TIMEOUT_SECS);
        if timeout_secs == 0 {
            return Err(Error::Config("hello_hs1_timeout_secs must be positive"));
        }
        let limits = Limits {
            budget: BudgetLimits {
                queue_bytes: Some(
                    int(&e, "limits", "queue_budget_bytes")?.unwrap_or(DEFAULT_QUEUE_BUDGET),
                ),
                linkdata_bytes: Some(
                    int(&e, "limits", "linkdata_budget_bytes")?.unwrap_or(DEFAULT_LINKDATA_BUDGET),
                ),
            },
            link_rate: rate("link_frames_burst", "link_frames_per_sec", d.link_rate)?,
            hello_rate: rate("hello_burst", "hello_per_sec", d.hello_rate)?,
            hello_timeout_ms: timeout_secs
                .checked_mul(1000)
                .ok_or(Error::Config("hello_hs1_timeout_secs is out of range"))?,
            drain_secs: int(&e, "shutdown", "drain_secs")?.unwrap_or(DEFAULT_DRAIN_SECS),
        };
        Ok(Self {
            listen,
            key_file,
            limits,
        })
    }

    /// Read and parse a configuration file.
    ///
    /// # Errors
    /// [`Error::Config`] if it cannot be read or parsed.
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|_| Error::Config("cannot read the file"))?;
        Self::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "# relay\n[listen]\ntor_loopback = \"127.0.0.1:7443\"  # C tor\n[access]\nkey_file = \"/k\"\n\
        [limits]\nqueue_budget_bytes = 1_049_600\nlinkdata_budget_bytes = 24_976\nlink_frames_burst = 3\n\
        link_frames_per_sec = 2\nhello_burst = 5\nhello_per_sec = 6\nhello_hs1_timeout_secs = 7\n\
        [shutdown]\ndrain_secs = 9\n";

    #[test]
    fn every_value_is_taken() -> Result<()> {
        let c = Config::parse(FULL)?;
        assert_eq!(c.listen.to_string(), "127.0.0.1:7443");
        assert_eq!(c.key_file, PathBuf::from("/k"));
        assert_eq!(
            c.limits,
            Limits {
                budget: BudgetLimits {
                    queue_bytes: Some(1_049_600),
                    linkdata_bytes: Some(24_976)
                },
                link_rate: Some(RateLimit {
                    burst: 3,
                    per_sec: 2
                }),
                hello_rate: Some(RateLimit {
                    burst: 5,
                    per_sec: 6
                }),
                hello_timeout_ms: 7000,
                drain_secs: 9,
            }
        );
        Ok(())
    }

    #[test]
    fn absent_limits_are_the_defaults() -> Result<()> {
        let c =
            Config::parse("[listen]\ntor_loopback = \"[::1]:1\"\n[access]\nkey_file = \"k\"\n")?;
        assert_eq!(c.limits, Limits::defaults());
        Ok(())
    }

    #[test]
    fn every_malformed_text_is_refused() {
        let base = "[listen]\ntor_loopback = \"127.0.0.1:1\"\n[access]\nkey_file = \"k\"\n";
        let bad = [
            String::new(),
            "[listen]\ntor_loopback = \"127.0.0.1:1\"\n".to_owned(),
            format!("{base}[limits]\nunknown = 1\n"),
            format!("{base}[nope]\n"),
            format!("{base}[limits]\nhello_burst = 1\nhello_burst = 2\n"),
            format!("{base}[limits]\nhello_burst = -1\n"),
            format!("{base}[limits]\nhello_burst = \"1\"\n"),
            format!("{base}[limits]\nhello_burst = 99999999999\n"),
            format!("{base}[limits]\nhello_hs1_timeout_secs = 0\n"),
            format!("{base}[limits]\nqueue_budget_bytes = 1_\n"),
            format!("{base}[limits]\nqueue_budget_bytes\n"),
            format!("{base}[limits\n"),
            "tor_loopback = \"127.0.0.1:1\"\n".to_owned(),
            "[listen]\ntor_loopback = \"10.0.0.1:1\"\n[access]\nkey_file = \"k\"\n".to_owned(),
            "[listen]\ntor_loopback = \"x\"\n[access]\nkey_file = \"k\"\n".to_owned(),
            "[listen]\ntor_loopback = 1\n[access]\nkey_file = \"k\"\n".to_owned(),
            "[listen]\ntor_loopback = \"127.0.0.1:1\n".to_owned(),
            "[listen]\ntor_loopback = \"a\\\"b\"\n".to_owned(),
        ];
        for b in &bad {
            assert!(Config::parse(b).is_err(), "accepted: {b:?}");
        }
        assert!(Config::read(std::path::Path::new("/nonexistent/secmp-relay.toml")).is_err());
    }

    #[test]
    fn values_and_comments_follow_the_subset() {
        assert_eq!(parse_value("\"a b\""), Ok(Value::Str("a b".to_owned())));
        assert_eq!(parse_value("1_000"), Ok(Value::Int(1000)));
        assert_eq!(parse_value("0"), Ok(Value::Int(0)));
        for bad in [
            "\"a\\b\"", "\"a\"b\"", "\"", "", "abc", "1x", "-1", "_1", "1_", "_",
        ] {
            assert!(parse_value(bad).is_err(), "{bad:?}");
        }
        assert_eq!(strip_comment("key = \"a#b\" # note"), "key = \"a#b\" ");
        assert_eq!(strip_comment("# only a comment"), "");
        assert_eq!(strip_comment("x = 1"), "x = 1");
        assert_eq!(strip_comment("x = \"#\""), "x = \"#\"");
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() -> Result<()> {
        let c = Config::parse(
            "[listen]\ntor_loopback = \"127.0.0.1:1\"\n[access]\nkey_file = \"/k#1\" # the key file\n",
        )?;
        assert_eq!(c.key_file, PathBuf::from("/k#1"));
        Ok(())
    }

    #[test]
    fn the_vector_limits_are_unlimited_rates() {
        let v = Limits::vectors();
        assert_eq!(v.link_rate, None);
        assert_eq!(v.hello_rate, None);
        assert_eq!(v.budget, BudgetLimits::vectors());
    }
}
