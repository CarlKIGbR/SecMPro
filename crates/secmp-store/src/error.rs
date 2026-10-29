// SPDX-License-Identifier: AGPL-3.0-or-later
//! The single error type of `secmp-store` (docs/06 §2: one uniform error type per crate). No variant carries a field,
//! an id, a path or a message of the database engine (CLAUDE.md §4): the caller learns which of four things went wrong,
//! never why in detail.

use core::fmt;

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The profile could not be unlocked: a wrong key, no key, or a file that is not a profile of this store. Uniform
    /// for every cause (CLAUDE.md §4).
    Unlock,
    /// The bundled SQLCipher is older than the pinned minimum, or a value is of a kind the store refuses to write
    /// (a view-once message, CS-3.4).
    Unsupported,
    /// The profile was written by a newer schema than this build knows.
    TooNew,
    /// The store could not complete the operation (I/O, a busy profile, a failed statement): nothing was changed.
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unlock => "secmp-store: the profile could not be unlocked",
            Self::Unsupported => "secmp-store: unsupported",
            Self::TooNew => "secmp-store: the profile is newer than this build",
            Self::Unavailable => "secmp-store: the store is unavailable",
        })
    }
}

impl std::error::Error for Error {}

/// Shorthand used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    /// G7-13 extra test: each error displays its fixed text, with no detail (uniform errors, `docs/06` §2).
    #[test]
    fn errors_display_fixed_text() {
        for (e, text) in [
            (
                Error::Unlock,
                "secmp-store: the profile could not be unlocked",
            ),
            (Error::Unsupported, "secmp-store: unsupported"),
            (
                Error::TooNew,
                "secmp-store: the profile is newer than this build",
            ),
            (Error::Unavailable, "secmp-store: the store is unavailable"),
        ] {
            assert_eq!(e.to_string(), text);
        }
    }
}
