// SPDX-License-Identifier: AGPL-3.0-or-later
//! M0 spike (a): SQLCipher via rusqlite `bundled-sqlcipher-vendored-openssl`. Prints `SPIKE-A OK` on success.
#![forbid(unsafe_code)]

use std::error::Error;

use rusqlite::Connection;

const KEY: &str = "spike-only-test-passphrase-not-a-secret";

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!("secmp-spike-a-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("spike.db");
    {
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "key", KEY)?;
        let version: String = conn.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
        let provider: String = conn.query_row("PRAGMA cipher_provider", [], |r| r.get(0))?;
        let provider_version: String = conn.query_row("PRAGMA cipher_provider_version", [], |r| r.get(0))?;
        println!("cipher_version = {version}; cipher_provider = {provider} {provider_version}");
        conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES ('hello from sqlcipher');")?;
    }
    {
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "key", KEY)?;
        let x: String = conn.query_row("SELECT x FROM t", [], |r| r.get(0))?;
        if x != "hello from sqlcipher" {
            return Err(format!("read back {x:?}").into());
        }
        println!("reopen with the right key: read back {x:?}");
    }
    {
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "key", "wrong key")?;
        match conn.query_row("SELECT count(*) FROM t", [], |r| r.get::<_, i64>(0)) {
            Ok(n) => return Err(format!("wrong key was accepted ({n} rows)").into()),
            Err(e) => println!("reopen with a wrong key fails as expected: {e}"),
        }
    }
    let bytes = std::fs::read(&path)?;
    let header = bytes.get(..16).ok_or("database file too short")?;
    if header == b"SQLite format 3\0" {
        return Err("database file has a plaintext SQLite header".into());
    }
    if bytes.windows(20).any(|w| w == b"hello from sqlcipher") {
        return Err("plaintext found in the database file".into());
    }
    println!("database file ({} bytes) has no plaintext header and no plaintext row", bytes.len());
    std::fs::remove_dir_all(&dir)?;
    println!("SPIKE-A OK ({} {})", std::env::consts::OS, std::env::consts::ARCH);
    Ok(())
}
