// SPDX-License-Identifier: AGPL-3.0-or-later
//! The command line (a hand-written parser, OPEN-M7-11 A) and the command lines of an open session. Neither parser echoes its
//! input: an argument or a line may hold a secret (the invitation URI, a passphrase typed in the wrong place).

use std::path::PathBuf;

use secmp_crypto::Zeroizing;

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
    /// `contacts list <dir> --passphrase-file F`: offline, the profile's contacts.
    ContactsList {
        /// The profile directory.
        dir: PathBuf,
        /// The passphrase file.
        passphrase_file: PathBuf,
    },
    /// `import <backup> <newdir> --passphrase-file F --backup-passphrase-file G`: a backup into a new profile.
    Import {
        /// The backup file.
        backup: PathBuf,
        /// The new profile's directory.
        dir: PathBuf,
        /// The new profile's passphrase file.
        passphrase_file: PathBuf,
        /// The backup's passphrase file.
        backup_passphrase_file: PathBuf,
    },
}

/// The command line is not one of the above.
#[derive(Debug, PartialEq, Eq)]
pub struct Usage;

/// The usage text (stderr).
pub const USAGE: &str = "usage:\n  secmp-cli\n  secmp-cli profile new <dir> --passphrase-file <file> [--relay <file>]\n  secmp-cli open <dir> --passphrase-file <file> [--direct] [--name <name>]\n  secmp-cli contacts list <dir> --passphrase-file <file>\n  secmp-cli import <backup> <newdir> --passphrase-file <file> --backup-passphrase-file <file>\n  in a session: invite create | invite accept <uri> | contacts list | contacts sas <id> | contacts verify <id> <digits> | status | identity rotate | rotate <id> | send <id> <text> | export <path> --backup-passphrase-file <file> [--confirm] [--force] | quit\n  note: an accepted invitation is consumed at the relay before it is stored; quitting during `accepting` loses it\n  note: a failed import leaves an empty profile in <newdir>; remove that directory before retrying\n";

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
        (Some("contacts"), Some("list")) => {
            let (dir, mut flags) = dir_and_flags(it)?;
            let command = Command::ContactsList {
                dir,
                passphrase_file: flags.value("--passphrase-file")?.ok_or(Usage)?.into(),
            };
            flags.finish()?;
            Ok(command)
        }
        (Some("import"), Some(backup)) if !backup.starts_with("--") => {
            let (dir, mut flags) = dir_and_flags(it)?;
            let command = Command::Import {
                backup: PathBuf::from(backup),
                dir,
                passphrase_file: flags.value("--passphrase-file")?.ok_or(Usage)?.into(),
                backup_passphrase_file: flags
                    .value("--backup-passphrase-file")?
                    .ok_or(Usage)?
                    .into(),
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

/// The longest line of an open session (bytes, without the newline); a longer one is dropped and answered as a usage error.
pub const LINE_MAX: usize = 65_536;

/// A line the user types into an open session. `Debug` prints the variant name only: a line may hold a secret (the URI, a
/// path, a text); a line is never compared with `==`.
pub enum Line {
    /// `invite create`.
    InviteCreate,
    /// `invite accept <uri>`: the URI is a secret.
    InviteAccept(Zeroizing<String>),
    /// `contacts list`.
    ContactsList,
    /// `contacts sas <id>`.
    ContactsSas(i64),
    /// `contacts verify <id> <digits…>`: the digits, their groups joined.
    ContactsVerify(i64, String),
    /// `status`.
    Status,
    /// `identity rotate`.
    IdentityRotate,
    /// `rotate <id>`.
    Rotate(i64),
    /// `send <id> <text…>`.
    Send(i64, String),
    /// `export <path> --backup-passphrase-file G [--confirm] [--force]`.
    Export {
        /// The file to create.
        path: PathBuf,
        /// The backup passphrase file.
        passphrase_file: PathBuf,
        /// The user's confirmation.
        confirm: bool,
        /// Also into a cloud-synchronised folder.
        force: bool,
    },
    /// `quit`.
    Quit,
}

impl core::fmt::Debug for Line {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InviteCreate => "InviteCreate",
            Self::InviteAccept(_) => "InviteAccept",
            Self::ContactsList => "ContactsList",
            Self::ContactsSas(_) => "ContactsSas",
            Self::ContactsVerify(..) => "ContactsVerify",
            Self::Status => "Status",
            Self::IdentityRotate => "IdentityRotate",
            Self::Rotate(_) => "Rotate",
            Self::Send(..) => "Send",
            Self::Export { .. } => "Export",
            Self::Quit => "Quit",
        })
    }
}

/// The flags of an `export` line: `--backup-passphrase-file G` once, `--confirm` and `--force` at most once each.
fn export_line(path: &str, flags: &str) -> Result<Line, Usage> {
    let (mut file, mut confirm, mut force) = (None, false, false);
    let mut words = flags.split(' ');
    while let Some(word) = words.next() {
        match word {
            "--backup-passphrase-file" if file.is_none() => {
                file = Some(words.next().filter(|w| !w.is_empty()).ok_or(Usage)?);
            }
            "--confirm" if !confirm => confirm = true,
            "--force" if !force => force = true,
            _ => return Err(Usage),
        }
    }
    Ok(Line::Export {
        path: PathBuf::from(path),
        passphrase_file: PathBuf::from(file.ok_or(Usage)?),
        confirm,
        force,
    })
}

/// Parse one line of an open session. Pure and total: every `&str` is a [`Line`] or a [`Usage`].
///
/// # Errors
/// [`Usage`] for an unknown verb, a missing or malformed argument.
pub fn parse_line(line: &str) -> Result<Line, Usage> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let mut words = line.splitn(3, ' ');
    match (words.next(), words.next(), words.next()) {
        (Some("invite"), Some("create"), None) => Ok(Line::InviteCreate),
        (Some("invite"), Some("accept"), Some(uri)) if !uri.is_empty() && !uri.contains(' ') => {
            Ok(Line::InviteAccept(Zeroizing::new(uri.to_owned())))
        }
        (Some("contacts"), Some("list"), None) => Ok(Line::ContactsList),
        (Some("contacts"), Some("sas"), Some(id)) => {
            Ok(Line::ContactsSas(id.parse().map_err(|_| Usage)?))
        }
        (Some("contacts"), Some("verify"), Some(rest)) => {
            let (id, groups) = rest.split_once(' ').ok_or(Usage)?;
            let digits: String = groups.split(' ').collect();
            if digits.is_empty() {
                return Err(Usage);
            }
            Ok(Line::ContactsVerify(id.parse().map_err(|_| Usage)?, digits))
        }
        (Some("status"), None, None) => Ok(Line::Status),
        (Some("identity"), Some("rotate"), None) => Ok(Line::IdentityRotate),
        (Some("rotate"), Some(id), None) => Ok(Line::Rotate(id.parse().map_err(|_| Usage)?)),
        (Some("export"), Some(path), Some(flags)) if !path.is_empty() => export_line(path, flags),
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
    fn the_one_shot_forms() {
        assert_eq!(
            parse(&args(&["contacts", "list", "d", "--passphrase-file", "f"])),
            Ok(Command::ContactsList {
                dir: "d".into(),
                passphrase_file: "f".into()
            })
        );
        assert_eq!(
            parse(&args(&[
                "import",
                "b",
                "n",
                "--backup-passphrase-file",
                "g",
                "--passphrase-file",
                "f"
            ])),
            Ok(Command::Import {
                backup: "b".into(),
                dir: "n".into(),
                passphrase_file: "f".into(),
                backup_passphrase_file: "g".into()
            })
        );
        for bad in [
            &["contacts", "list"][..],
            &["contacts", "list", "d"],
            &["import", "b"],
            &["import", "b", "n", "--passphrase-file", "f"],
            &["import", "b", "n", "--backup-passphrase-file", "g"],
        ] {
            assert_eq!(parse(&args(bad)), Err(Usage), "{bad:?}");
        }
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
        assert!(matches!(
            parse_line("invite create"),
            Ok(Line::InviteCreate)
        ));
        assert!(matches!(
            parse_line("invite accept secmp://i/abc"),
            Ok(Line::InviteAccept(u)) if u.as_str() == "secmp://i/abc"
        ));
        assert!(matches!(
            parse_line("contacts list\r"),
            Ok(Line::ContactsList)
        ));
        assert!(matches!(
            parse_line("send 12 hello  wide world"),
            Ok(Line::Send(12, t)) if t == "hello  wide world"
        ));
        assert!(matches!(parse_line("quit"), Ok(Line::Quit)));
        assert!(matches!(
            parse_line("contacts sas 3"),
            Ok(Line::ContactsSas(3))
        ));
        assert!(matches!(
            parse_line("contacts verify 3 12345 67890"),
            Ok(Line::ContactsVerify(3, d)) if d == "1234567890"
        ));
        assert!(matches!(parse_line("status"), Ok(Line::Status)));
        assert!(matches!(
            parse_line("identity rotate"),
            Ok(Line::IdentityRotate)
        ));
        assert!(matches!(parse_line("rotate 4"), Ok(Line::Rotate(4))));
        assert!(matches!(
            parse_line("export /x/b.smpb --backup-passphrase-file g --confirm --force"),
            Ok(Line::Export { path, passphrase_file, confirm: true, force: true })
                if path.to_str() == Some("/x/b.smpb") && passphrase_file.to_str() == Some("g")
        ));
        assert!(matches!(
            parse_line("export b --backup-passphrase-file g"),
            Ok(Line::Export {
                confirm: false,
                force: false,
                ..
            })
        ));
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
            "contacts sas",
            "contacts sas x",
            "contacts verify 3",
            "contacts verify 3 ",
            "contacts verify x 1",
            "status now",
            "identity",
            "identity rotate now",
            "rotate",
            "rotate x",
            "rotate 1 2",
            "export",
            "export b",
            "export b --confirm",
            "export b --backup-passphrase-file",
            "export b --backup-passphrase-file g --confirm --confirm",
            "export b --backup-passphrase-file g --bogus",
        ] {
            assert!(parse_line(bad).is_err(), "{bad:?}");
        }
        // the debug form of a line never shows what it holds
        let shown = format!("{:?}", parse_line("invite accept secmp://i/secret"));
        assert!(!shown.contains("secret"), "{shown}");
    }
}
