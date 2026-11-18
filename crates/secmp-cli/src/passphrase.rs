// SPDX-License-Identifier: AGPL-3.0-or-later
//! The passphrase (OPEN-M7-13 A, Q282): only from a file named by `--passphrase-file` — never from the command line (visible
//! to every process of the machine) and never from the environment. On Unix the file must not be readable by group or other
//! (`mode & 0o077 == 0`); the bytes are read into a zeroizing buffer and one trailing newline is dropped. On Windows there is
//! no check of the file's access control list (HB-20).

use std::io::Read as _;
use std::path::Path;

use secmp_crypto::Zeroizing;

/// The longest passphrase read: a longer file is refused.
const MAX_LEN: usize = 1_024;

/// Why the passphrase could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Group or others can read the file (Unix).
    Mode,
    /// The file is missing, unreadable, empty or too long.
    Unreadable,
}

/// Read the passphrase in `path`.
///
/// # Errors
/// [`Refusal::Mode`] for a file others can access; [`Refusal::Unreadable`] otherwise.
pub fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let file = std::fs::File::open(path).map_err(|_| Refusal::Unreadable)?;
    let meta = file.metadata().map_err(|_| Refusal::Unreadable)?;
    if !meta.is_file() {
        return Err(Refusal::Unreadable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Refusal::Mode);
        }
    }
    // one allocation of the final size: a growing buffer would leave copies of the passphrase in freed memory
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_LEN.saturating_add(2)));
    let limit = u64::try_from(MAX_LEN.saturating_add(1)).map_err(|_| Refusal::Unreadable)?;
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Unreadable)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.len() > MAX_LEN {
        return Err(Refusal::Unreadable);
    }
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt as _;

    fn file(name: &str, content: &[u8], mode: u32) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = std::env::temp_dir().join(format!("secmp-cli-pass-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        std::fs::write(&path, content)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        Ok(path)
    }

    #[test]
    fn the_file_rules() -> Result<(), std::io::Error> {
        let ok = file("ok", b"correct horse\n", 0o600)?;
        assert_eq!(
            read(&ok).as_deref().map(Vec::as_slice),
            Ok(&b"correct horse"[..])
        );
        let two = file("two", b"abc\n\n", 0o400)?;
        assert_eq!(read(&two).as_deref().map(Vec::as_slice), Ok(&b"abc\n"[..]));
        assert_eq!(read(&file("group", b"x", 0o640)?), Err(Refusal::Mode));
        assert_eq!(read(&file("other", b"x", 0o604)?), Err(Refusal::Mode));
        assert_eq!(
            read(&file("empty", b"\n", 0o600)?),
            Err(Refusal::Unreadable)
        );
        assert_eq!(
            read(&file("long", &[b'a'; MAX_LEN + 1], 0o600)?),
            Err(Refusal::Unreadable)
        );
        assert_eq!(
            read(&ok.with_file_name("missing")),
            Err(Refusal::Unreadable)
        );
        Ok(())
    }
}
