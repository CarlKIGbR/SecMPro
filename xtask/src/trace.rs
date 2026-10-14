// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runner resource trace (M6-15): with `SECMP_RUNNER_TRACE` set, a background thread writes one `runner-trace` line
//! every 20 s to stdout (memory, swap, disk, largest process), so that a runner shutdown in a long step leaves the
//! resource state in the job log. Errors are ignored; unreadable fields are `-`.

use std::process::Command;
use std::time::Duration;

use crate::util::say;

/// Start the trace thread if `SECMP_RUNNER_TRACE` is set and not empty; `true` if it was started. The thread ends with
/// the process.
pub(crate) fn start_if_enabled() -> bool {
    if std::env::var_os("SECMP_RUNNER_TRACE").is_none_or(|v| v.is_empty()) {
        return false;
    }
    std::thread::spawn(|| {
        loop {
            print_line();
            std::thread::sleep(Duration::from_secs(20));
        }
    });
    true
}

fn run(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn print_line() {
    let now = run("date", &["-u", "+%FT%TZ"]);
    let now = now.trim();
    say(&line(
        if now.is_empty() { "-" } else { now },
        &run("free", &["-m"]),
        &run("df", &["-m", "/"]),
        &run("ps", &["-eo", "rss,comm", "--sort=-rss"]),
    ));
}

/// The `field`-th (0-based) whitespace-separated column of the first line of `text` starting with `prefix`.
fn column(text: &str, prefix: &str, field: usize) -> String {
    text.lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.split_whitespace().nth(field))
        .unwrap_or("-")
        .to_owned()
}

/// One trace line from the outputs of `free -m`, `df -m /` and `ps -eo rss,comm --sort=-rss`.
pub(crate) fn line(now_utc: &str, free_m: &str, df_m: &str, ps: &str) -> String {
    let disk = df_m
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(3))
        .unwrap_or("-");
    let top = ps
        .lines()
        .nth(1)
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .and_then(|l| l.split_once(char::is_whitespace))
        .map_or_else(
            || "- -".to_owned(),
            |(rss, comm)| format!("{rss} {}", comm.trim()),
        );
    format!(
        "runner-trace {now_utc} mem_used_MiB={} mem_avail_MiB={} swap_used_MiB={} disk_avail_MiB={disk} top={top}",
        column(free_m, "Mem:", 2),
        column(free_m, "Mem:", 6),
        column(free_m, "Swap:", 2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_formats_all_fields() {
        let free = "              total        used        free      shared  buff/cache   available\nMem:           15990        6123        1200          10        8667        9500\nSwap:           4095         300        3795\n";
        let df = "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/root 73000 60000 13000 83% /\n";
        let ps = "  RSS COMMAND\n5242880 cbmc\n";
        assert_eq!(
            line("2026-10-14T16:00:00Z", free, df, ps),
            "runner-trace 2026-10-14T16:00:00Z mem_used_MiB=6123 mem_avail_MiB=9500 swap_used_MiB=300 disk_avail_MiB=13000 top=5242880 cbmc"
        );
    }

    #[test]
    fn line_tolerates_missing_input() {
        assert_eq!(
            line("2026-10-14T16:00:00Z", "", "", ""),
            "runner-trace 2026-10-14T16:00:00Z mem_used_MiB=- mem_avail_MiB=- swap_used_MiB=- disk_avail_MiB=- top=- -"
        );
    }

    #[test]
    fn disabled_without_env() {
        assert!(std::env::var_os("SECMP_RUNNER_TRACE").is_none());
        assert!(!start_if_enabled());
    }
}
