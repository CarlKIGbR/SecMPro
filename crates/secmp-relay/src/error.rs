// SPDX-License-Identifier: AGPL-3.0-or-later
//! The crate's one error type. A connection never sees it: a rejected record or frame is a teardown (spec §8.5),
//! and the executor's answers are wire values (D.2). These errors are the operator's: starting the relay, the key
//! file, the configuration. No message carries a secret, a key, an id or an address of a client.

use core::fmt;

/// An error of the relay process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The configuration is missing, unreadable or invalid; the reason names the rule, never a value.
    Config(&'static str),
    /// The key file is missing, unreadable or malformed.
    KeyFile,
    /// No key generation is valid at the current time.
    NoValidKeys,
    /// An I/O operation of the operator path (binding the listener, writing the key file) failed.
    Io,
    /// Randomness or locked memory is unavailable.
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(why) => write!(f, "configuration: {why}"),
            Self::KeyFile => f.write_str("key file missing, unreadable or malformed"),
            Self::NoValidKeys => f.write_str("no key generation is valid now"),
            Self::Io => f.write_str("i/o error"),
            Self::Unavailable => f.write_str("randomness or locked memory unavailable"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

/// `Result` with the crate [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_condition_only() {
        assert_eq!(
            Error::Config("unknown key").to_string(),
            "configuration: unknown key"
        );
        assert_eq!(
            Error::KeyFile.to_string(),
            "key file missing, unreadable or malformed"
        );
        assert_eq!(
            Error::NoValidKeys.to_string(),
            "no key generation is valid now"
        );
        assert_eq!(Error::Io.to_string(), "i/o error");
        assert_eq!(
            Error::Unavailable.to_string(),
            "randomness or locked memory unavailable"
        );
        assert_eq!(Error::from(std::io::Error::other("x")), Error::Io);
    }
}
