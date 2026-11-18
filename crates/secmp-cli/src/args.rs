// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line (a hand-written parser, OPEN-M7-11 A) and the command lines of an open session. Neither parser echoes its
//! input: an argument or a line may hold a secret (the invitation URI, a passphrase typed in the wrong place).

use std::path::PathBuf;

/// What the program was started for.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// No arguments: print the banner.
    Banner,
    /// `profile new <dir> --passphrase-file F [--relay R]`.
    ProfileNew {
        /// The profile directory.
        dir: PathBuf,
        /// The passphrase file.
        passphrase_file: PathBuf,
        /// The relay reference file.
        relay: Option<PathBuf>,
    },
    /// `open <dir> --passphrase-file F [--direct] [--name N]`.
    Open {
        /// The profile directory.
        dir: PathBuf,
        /// The passphrase file.
        passphrase_file: PathBuf,
        /// Direct TLS instead of Tor.
        direct: bool,
        /// The name presented in a handshake.
        name: Option<String>,
    },
}

/// The command line is not one of the above.
#[derive(Debug, PartialEq, Eq)]
pub struct Usage;

/// The usage text (stderr).
pub const USAGE: &str = "usage:\n  secmp-cli\n  secmp-cli profile new <dir> --passphrase-file <file> [--relay <file>]\n  secmp-cli open <dir> --passphrase-file <file> [--direct] [--name <name>]\n";

/// Parse the arguments after the program name.
///
/// # Errors
/// [`Usage`] for anything else: an unknown verb or flag (`--passphrase` among them), a missing or repeated value.
pub fn parse(args: &[String]) -> Result<Command, Usage> {
    let mut it = args.iter().map(String::as_str);
    match (it.next(), it.next()) {
        (None, _) => Ok(Command::Banner),
        (Some("profile"), Some("new")) => {
            let (dir, mut flags) = dir_and_flags(it)?;
            let command = Command::ProfileNew {
                dir,
                passphrase_file: flags.value("--passphrase-file")?.ok_or(Usage)?.into(),
                relay: flags.value("--relay")?.map(PathBuf::from),
            };
            flags.finish()?;
            Ok(command)
        }
        (Some("open"), Some(dir)) => {
            let mut flags = Flags::collect(it)?;
            let command = Command::Open {
                dir: PathBuf::from(dir),
                passphrase_file: flags.value("--passphrase-file")?.ok_or(Usage)?.into(),
                direct: flags.switch("--direct")?,
                name: flags.value("--name")?.map(str::to_owned),
            };
            flags.finish()?;
            Ok(command)
        }
        _ => Err(Usage),
    }
}

fn dir_and_flags<'a>(mut it: impl Iterator<Item = &'a str>) -> Result<(PathBuf, Flags<'a>), Usage> {
    let dir = it.next().filter(|d| !d.starts_with("--")).ok_or(Usage)?;
    Ok((PathBuf::from(dir), Flags::collect(it)?))
}

/// How a flag appeared.
enum Seen<'a> {
    /// Not at all.
    No,
    /// Without a value.
    Bare,
    /// With a value.
    With(&'a str),
}

/// The `--flag [value]` words after the positional arguments.
struct Flags<'a>(Vec<(&'a str, Option<&'a str>)>);

impl<'a> Flags<'a> {
    /// Split the words into flags; a word after a flag that does not start with `--` is that flag's value.
    fn collect(it: impl Iterator<Item = &'a str>) -> Result<Self, Usage> {
        let mut words = it.peekable();
        let mut flags = Vec::new();
        while let Some(word) = words.next() {
            if !word.starts_with("--") {
                return Err(Usage);
            }
            let value = words.next_if(|w| !w.starts_with("--"));
            flags.push((word, value));
        }
        Ok(Self(flags))
    }

    /// Take `name` with its value: `None` if absent; a missing value or a repeated flag is a usage error.
    fn value(&mut self, name: &str) -> Result<Option<&'a str>, Usage> {
        match self.take(name)? {
            Seen::No => Ok(None),
            Seen::With(v) => Ok(Some(v)),
            Seen::Bare => Err(Usage),
        }
    }

    /// Take the switch `name` (no value).
    fn switch(&mut self, name: &str) -> Result<bool, Usage> {
        match self.take(name)? {
            Seen::No => Ok(false),
            Seen::Bare => Ok(true),
            Seen::With(_) => Err(Usage),
        }
    }

    fn take(&mut self, name: &str) -> Result<Seen<'a>, Usage> {
        let mut found = self.0.iter().filter(|(n, _)| *n == name);
        let first = found.next().map(|(_, v)| *v);
        if found.next().is_some() {
            return Err(Usage);
        }
        self.0.retain(|(n, _)| *n != name);
        Ok(match first {
            None => Seen::No,
            Some(None) => Seen::Bare,
            Some(Some(v)) => Seen::With(v),
        })
    }

    /// No flag may be left over.
    fn finish(self) -> Result<(), Usage> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Usage)
        }
    }
}

/// A line the user types into an open session.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// `invite create`.
    InviteCreate,
    /// `invite accept <uri>`.
    InviteAccept(String),
    /// `contacts list`.
    ContactsList,
    /// `send <id> <text…>`.
    Send(i64, String),
    /// `quit`.
    Quit,
}

/// Parse one line of an open session.
///
/// # Errors
/// [`Usage`] for an unknown verb, a missing or malformed argument.
pub fn parse_line(line: &str) -> Result<Line, Usage> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let mut words = line.splitn(3, ' ');
    match (words.next(), words.next(), words.next()) {
        (Some("invite"), Some("create"), None) => Ok(Line::InviteCreate),
        (Some("invite"), Some("accept"), Some(uri)) if !uri.is_empty() && !uri.contains(' ') => {
            Ok(Line::InviteAccept(uri.to_owned()))
        }
        (Some("contacts"), Some("list"), None) => Ok(Line::ContactsList),
        (Some("send"), Some(id), Some(text)) if !text.is_empty() => {
            Ok(Line::Send(id.parse().map_err(|_| Usage)?, text.to_owned()))
        }
        (Some("quit"), None, None) => Ok(Line::Quit),
        _ => Err(Usage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn the_command_line_forms() {
        assert_eq!(parse(&[]), Ok(Command::Banner));
        assert_eq!(
            parse(&args(&["profile", "new", "d", "--passphrase-file", "f"])),
            Ok(Command::ProfileNew {
                dir: "d".into(),
                passphrase_file: "f".into(),
                relay: None
            })
        );
        assert_eq!(
            parse(&args(&[
                "open",
                "d",
                "--direct",
                "--passphrase-file",
                "f",
                "--name",
                "A"
            ])),
            Ok(Command::Open {
                dir: "d".into(),
                passphrase_file: "f".into(),
                direct: true,
                name: Some("A".to_owned())
            })
        );
    }

    #[test]
    fn everything_else_is_usage() {
        for bad in [
            &["frobnicate"][..],
            &["open"],
            &["open", "d"],
            &["open", "d", "--passphrase", "secret"],
            &["open", "d", "--passphrase-file"],
            &[
                "open",
                "d",
                "--passphrase-file",
                "f",
                "--passphrase-file",
                "g",
            ],
            &["open", "d", "--passphrase-file", "f", "--direct", "x"],
            &["open", "d", "--passphrase-file", "f", "stray"],
            &["profile"],
            &["profile", "new"],
            &["profile", "new", "--passphrase-file", "f"],
            &["profile", "new", "d"],
        ] {
            assert_eq!(parse(&args(bad)), Err(Usage), "{bad:?}");
        }
    }

    #[test]
    fn the_session_lines() {
        assert_eq!(parse_line("invite create"), Ok(Line::InviteCreate));
        assert_eq!(
            parse_line("invite accept secmp://i/abc"),
            Ok(Line::InviteAccept("secmp://i/abc".to_owned()))
        );
        assert_eq!(parse_line("contacts list\r"), Ok(Line::ContactsList));
        assert_eq!(
            parse_line("send 12 hello  wide world"),
            Ok(Line::Send(12, "hello  wide world".to_owned()))
        );
        assert_eq!(parse_line("quit"), Ok(Line::Quit));
        for bad in [
            "",
            "invite",
            "invite accept",
            "send",
            "send 1",
            "send x y",
            "send 1 ",
            "quit now",
            "contacts",
            "bogus line",
            "invite create now",
        ] {
            assert_eq!(parse_line(bad), Err(Usage), "{bad:?}");
        }
    }
}
