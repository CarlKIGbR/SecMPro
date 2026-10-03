// SPDX-License-Identifier: AGPL-3.0-or-later
//! Error type, console output and process execution shared by all xtask commands.

use std::ffi::OsStr;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The single xtask error: a human-readable message. xtask never handles secrets.
#[derive(Debug)]
pub(crate) struct Error(pub(crate) String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(format!("I/O error: {e}"))
    }
}

/// Result alias used throughout xtask.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Return early with a formatted [`Error`].
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::util::Error(format!($($arg)*)))
    };
}
pub(crate) use bail;

/// Write one line to stdout. The workspace denies the `print!` family, so output is written explicitly; a
/// closed stdout cannot be reported anywhere else, so a failed write is deliberately ignored.
pub(crate) fn say(msg: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{msg}");
}

/// Write one line to stderr (see [`say`]).
pub(crate) fn warn(msg: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{msg}");
}

/// A command line to execute, echoed before it runs.
#[derive(Clone, Debug)]
pub(crate) struct Cmd {
    program: String,
    args: Vec<String>,
    dir: Option<PathBuf>,
    envs: Vec<(String, String)>,
    removed: Vec<String>,
}

/// Captured result of a command that is allowed to fail.
pub(crate) struct Captured {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Cmd {
    pub(crate) fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            dir: None,
            envs: Vec::new(),
            removed: Vec::new(),
        }
    }

    /// `cargo` of the pinned toolchain: the `CARGO` variable set by `cargo run`, else `cargo` from `PATH`.
    pub(crate) fn cargo() -> Self {
        Self::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
    }

    /// `cargo` of another toolchain via `rustup run` (used for the pinned nightly).
    pub(crate) fn cargo_on(toolchain: &str) -> Self {
        Self::new("rustup").args(["run", toolchain, "cargo"])
    }

    pub(crate) fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub(crate) fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }

    pub(crate) fn dir(mut self, d: impl AsRef<Path>) -> Self {
        self.dir = Some(d.as_ref().to_path_buf());
        self
    }

    /// Set an environment variable for the child (shown in the echoed command line).
    pub(crate) fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Run without the environment variable `key` (whatever the caller's environment holds).
    pub(crate) fn env_remove(mut self, key: impl Into<String>) -> Self {
        self.removed.push(key.into());
        self
    }

    fn display(&self) -> String {
        let mut s = String::new();
        for k in &self.removed {
            s.push_str("-u ");
            s.push_str(k);
            s.push(' ');
        }
        for (k, v) in &self.envs {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push(' ');
        }
        s.push_str(&self.program);
        for a in &self.args {
            s.push(' ');
            if a.contains(' ') {
                s.push('\'');
                s.push_str(a);
                s.push('\'');
            } else {
                s.push_str(a);
            }
        }
        s
    }

    fn command(&self) -> Command {
        let mut c = Command::new(OsStr::new(&self.program));
        c.args(&self.args);
        for k in &self.removed {
            c.env_remove(k);
        }
        c.envs(self.envs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        if let Some(d) = &self.dir {
            c.current_dir(d);
        }
        c
    }

    /// Run with inherited stdio; a non-zero exit status is an error.
    pub(crate) fn run(&self) -> Result<()> {
        say(&format!("$ {}", self.display()));
        let status = self
            .command()
            .status()
            .map_err(|e| Error(format!("cannot start `{}`: {e}", self.program)))?;
        if status.success() {
            Ok(())
        } else {
            bail!("`{}` failed with {status}", self.display())
        }
    }

    /// Run and return stdout; stderr is inherited; a non-zero exit status is an error.
    pub(crate) fn read(&self) -> Result<String> {
        let out = self
            .command()
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| Error(format!("cannot start `{}`: {e}", self.program)))?;
        if !out.status.success() {
            bail!("`{}` failed with {}", self.display(), out.status);
        }
        String::from_utf8(out.stdout)
            .map_err(|_| Error(format!("`{}` printed non-UTF-8 output", self.display())))
    }

    /// Run, echo, and capture stdout and stderr without treating failure as an error.
    pub(crate) fn capture(&self) -> Result<Captured> {
        say(&format!("$ {}", self.display()));
        let out = self
            .command()
            .output()
            .map_err(|e| Error(format!("cannot start `{}`: {e}", self.program)))?;
        Ok(Captured {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Start with stdin closed and stdout and stderr into `log` (created or truncated), echoing the command line;
    /// the caller polls and reaps the child (ADR-045 Amendment 1: a gate with its own wall-clock budget).
    pub(crate) fn spawn_logged(&self, log: &Path) -> Result<std::process::Child> {
        if let Some(dir) = log.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let out = std::fs::File::create(log)?;
        let err = out.try_clone()?;
        say(&format!("$ {} > {}", self.display(), log.display()));
        self.command()
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|e| Error(format!("cannot start `{}`: {e}", self.program)))
    }

    /// True if the program can be started at all (used to detect missing tools).
    pub(crate) fn exists(&self) -> bool {
        self.command()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }
}

/// Recursively list files below `dir` whose file name satisfies `pred`, skipping `target` directories and
/// hidden directories. The result is sorted for deterministic output.
pub(crate) fn walk_files(dir: &Path, pred: &dyn Fn(&Path) -> bool) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry.file_type()?.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    stack.push(path);
                }
            } else if pred(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Path relative to `root` for display (falls back to the full path).
pub(crate) fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .display()
        .to_string()
        .replace('\\', "/")
}
