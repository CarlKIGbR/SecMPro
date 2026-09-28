// SPDX-License-Identifier: AGPL-3.0-or-later
//! Calendar arithmetic for the dependency cooldown check.
//!
//! xtask never reads the local wall clock (`SystemTime::now` is disallowed workspace-wide, docs/06 §2): the
//! reference time is the `Date` header of the crates.io index response, so the check measures publish age on
//! crates.io's own clock. Timestamps are seconds since the Unix epoch (UTC).

use crate::util::{Error, Result, bail};

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's `days_from_civil`), with checked
/// arithmetic throughout.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = if y >= 0 { y } else { y.checked_sub(399)? }.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn to_epoch(year: i64, month: i64, day: i64, h: i64, m: i64, s: i64) -> Option<i64> {
    if !(0..=23).contains(&h) || !(0..=59).contains(&m) || !(0..=60).contains(&s) {
        return None;
    }
    days_from_civil(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(h.checked_mul(3_600)?)?
        .checked_add(m.checked_mul(60)?)?
        .checked_add(s)
}

fn num(s: &str) -> Result<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        bail!("not a number: {s:?}");
    }
    s.parse::<i64>()
        .map_err(|_| Error(format!("not a number: {s:?}")))
}

/// Parse an RFC 3339 UTC timestamp as used by the crates.io index `pubtime` field, e.g.
/// `2026-09-21T18:39:40Z` (fractional seconds are accepted and truncated).
pub(crate) fn parse_rfc3339_utc(s: &str) -> Result<i64> {
    let Some(body) = s.strip_suffix('Z') else {
        bail!("timestamp is not UTC (no trailing Z): {s:?}")
    };
    let (date, time) = body
        .split_once('T')
        .ok_or_else(|| Error(format!("malformed timestamp: {s:?}")))?;
    let time = time.split_once('.').map_or(time, |(whole, _frac)| whole);
    let date_parts: Vec<&str> = date.split('-').collect();
    let time_parts: Vec<&str> = time.split(':').collect();
    let (&[year, month, day], &[hour, minute, second]) =
        (date_parts.as_slice(), time_parts.as_slice())
    else {
        bail!("malformed timestamp: {s:?}")
    };
    to_epoch(
        num(year)?,
        num(month)?,
        num(day)?,
        num(hour)?,
        num(minute)?,
        num(second)?,
    )
    .ok_or_else(|| Error(format!("timestamp out of range: {s:?}")))
}

/// Parse an HTTP `Date` header value in IMF-fixdate form (RFC 9110 §5.6.7), e.g.
/// `Mon, 28 Sep 2026 15:49:34 GMT`.
pub(crate) fn parse_http_date(s: &str) -> Result<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = s.split_whitespace().collect();
    let &[_weekday, day, month, year, time, "GMT"] = parts.as_slice() else {
        bail!("unsupported HTTP date: {s:?}")
    };
    let month_index = MONTHS
        .iter()
        .position(|m| *m == month)
        .ok_or_else(|| Error(format!("unsupported HTTP date month: {s:?}")))?;
    let month_number = i64::try_from(month_index)
        .ok()
        .and_then(|i| i.checked_add(1))
        .ok_or_else(|| Error(format!("unsupported HTTP date month: {s:?}")))?;
    let t: Vec<&str> = time.split(':').collect();
    let &[h, mi, se] = t.as_slice() else {
        bail!("unsupported HTTP date time: {s:?}")
    };
    to_epoch(
        num(year)?,
        month_number,
        num(day)?,
        num(h)?,
        num(mi)?,
        num(se)?,
    )
    .ok_or_else(|| Error(format!("HTTP date out of range: {s:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() -> Result<()> {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z")?, 0);
        // Expected values computed independently with Python: calendar.timegm(datetime(...).timetuple()).
        // 2000-03-01 (leap-year boundary): 11_017 days after the epoch.
        assert_eq!(parse_rfc3339_utc("2000-03-01T00:00:00Z")?, 11_017 * 86_400);
        assert_eq!(parse_rfc3339_utc("2026-09-21T18:39:40Z")?, 1_790_015_980);
        assert_eq!(
            parse_rfc3339_utc("2026-09-21T18:39:40.123Z")?,
            1_790_015_980
        );
        Ok(())
    }

    #[test]
    fn http_date_matches_rfc3339() -> Result<()> {
        assert_eq!(
            parse_http_date("Mon, 28 Sep 2026 15:49:34 GMT")?,
            parse_rfc3339_utc("2026-09-28T15:49:34Z")?
        );
        Ok(())
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        for bad in [
            "",
            "2026-09-21T18:39:40",
            "2026-13-01T00:00:00Z",
            "2026-09-21 18:39:40Z",
            "x-09-21T18:39:40Z",
        ] {
            assert!(parse_rfc3339_utc(bad).is_err(), "{bad:?} must be rejected");
        }
        for bad in [
            "",
            "Mon, 28 Sep 2026 15:49:34 UTC",
            "Mon, 28 Foo 2026 15:49:34 GMT",
            "28 Sep 2026",
        ] {
            assert!(parse_http_date(bad).is_err(), "{bad:?} must be rejected");
        }
    }
}
