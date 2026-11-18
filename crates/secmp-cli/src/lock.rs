// SPDX-License-Identifier: AGPL-3.0-or-later
//! The single-writer lock of an open profile (OPEN-M7-12): `<dir>/cli.lock`, an advisory lock the operating system drops when
//! the process ends, however it ends (a killed process leaves no stale lock).

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

/// The lock file's name inside the profile directory.
const NAME: &str = "cli.lock";

/// Why the lock was not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another `secmp-cli` holds it.
    Busy,
    /// The file could not be created or locked.
    Unavailable,
}

/// The held lock; it is released when this is dropped or the process ends.
#[derive(Debug)]
pub struct Lock {
    _file: File,
}

impl Lock {
    /// Take the lock of the profile in `dir`, without waiting.
    ///
    /// # Errors
    /// [`Refusal::Busy`] if it is held; [`Refusal::Unavailable`] if the directory has no such file to lock.
    pub fn acquire(dir: &Path) -> Result<Self, Refusal> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(NAME))
            .map_err(|_| Refusal::Unavailable)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(Refusal::Busy),
            Err(TryLockError::Error(_)) => Err(Refusal::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second holder is `Busy` while the first lives; the lock is free again once it is dropped; a directory that does not
    /// exist is `Unavailable`.
    #[test]
    fn one_holder_at_a_time() -> Result<(), std::io::Error> {
        let dir = std::env::temp_dir().join(format!("secmp-cli-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let first = Lock::acquire(&dir);
        assert!(first.is_ok());
        assert_eq!(Lock::acquire(&dir).err(), Some(Refusal::Busy));
        drop(first);
        assert!(Lock::acquire(&dir).is_ok());
        assert_eq!(
            Lock::acquire(&dir.join("absent")).err(),
            Some(Refusal::Unavailable)
        );
        Ok(())
    }
}
