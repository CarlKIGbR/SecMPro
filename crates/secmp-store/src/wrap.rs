// SPDX-License-Identifier: AGPL-3.0-or-later
//! The passphrase wrap of a profile's master key (CS-3.2 `docs/04:53`; ADR-053 items 1, 2): `<profile>/wrap` holds
//!
//! ```text
//! wrap = ver(0x01) ‖ salt(16) ‖ params(m u32 ‖ t u32 ‖ p u32) ‖ N(24) ‖ CAEAD.Seal(KEK, N, AD = "SecMP-STORE/1 wrap" ‖ ver ‖ salt ‖ params, MK_profile)
//! KEK  = Argon2id(P = passphrase, S = salt, p = 4, T = 32, m = 262 144 KiB, t = 3, v = 0x13, K = X = empty)
//! ```
//!
//! = 133 bytes (a plaintext file: it reveals the parameters and the salt only). **Unlock** decides from the file bytes
//! alone, before any KDF work, that the length is 133, `ver` is 0x01 and `params` is [`Argon2Params::PROFILE`] (a crafted
//! file cannot demand other work, and the check reads no passphrase); then it runs Argon2id once and `CAEAD.Open` once —
//! every failure is the one [`Error::Unlock`] (Q123). [`Unlocked`] holds `MK_profile`, `K_db` and the nine table keys,
//! each in a locked page.

use std::path::Path;

use secmp_crypto::{Caead, Label, argon2id_locked};

use crate::error::{Error, Result};
use crate::keys::{TableKeys, derive};
use crate::secrets::StoreKey;
use crate::store::DbKey;

/// The file of the wrap inside a profile directory.
pub const WRAP_FILE: &str = "wrap";
/// The wrap format byte.
const VER: u8 = 0x01;
/// The length of a wrap: `ver ‖ salt ‖ params ‖ N ‖ COM ‖ MK ‖ tag`.
pub const WRAP_LEN: usize = 1 + 16 + 12 + 24 + 32 + 32 + 16;
const _: () = assert!(WRAP_LEN == 133);

/// The Argon2id cost parameters of a wrap (RFC 9106 §3.1; CS-3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Params {
    /// The parameters of a profile (CS-3.2; ADR-053 item 1): m = 262 144 KiB (256 MiB), t = 3, p = 4.
    pub const PROFILE: Self = Self {
        m_kib: 262_144,
        t: 3,
        p: 4,
    };

    /// The small parameters of the known-answer and constant-time rows (feature `kat`; never accepted by [`unlock`]).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn kat_small() -> Self {
        Self {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    /// `m u32 ‖ t u32 ‖ p u32`, big-endian.
    #[must_use]
    pub fn encode(&self) -> [u8; 12] {
        let mut b = [0_u8; 12];
        for (dst, v) in b.chunks_mut(4).zip([self.m_kib, self.t, self.p]) {
            dst.copy_from_slice(&v.to_be_bytes());
        }
        b
    }
}

/// `KEK = Argon2id(P, S = salt, params, T = 32, v = 0x13)` in a locked page (ADR-053 item 1).
fn kek(passphrase: &[u8], salt: &[u8; 16], params: Argon2Params) -> Result<StoreKey> {
    #[cfg(any(test, feature = "kat"))]
    crate::kat::note_argon2_call();
    // spec §3.4; ADR-053 item 1
    let k = argon2id_locked::<32>(passphrase, salt, params.m_kib, params.t, params.p)
        .map_err(|_| Error::Unlock)?;
    Ok(StoreKey::new(k))
}

/// The AD of a wrap: `"SecMP-STORE/1 wrap" ‖ ver ‖ salt ‖ params` (ADR-053 item 2).
fn ad(salt: &[u8; 16], params: &[u8; 12]) -> Vec<u8> {
    [Label::StoreWrap.as_bytes(), &[VER], salt, params].concat()
}

/// An unlocked profile: `MK_profile` in a locked page; `K_db` and the table keys are derived from it on demand (ADR-053
/// items 3, 4), each in its own locked page.
pub struct Unlocked {
    mk: StoreKey,
}

impl Unlocked {
    const fn from_mk(mk: StoreKey) -> Self {
        Self { mk }
    }

    /// The key of the profile's database: `K_db` and the nine table keys (ADR-053 items 3, 4).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if locked memory is unavailable.
    pub fn db_key(&self) -> Result<DbKey> {
        let db = derive(self.mk.locked(), Label::StoreDb)?;
        Ok(DbKey::from_unlocked(
            db.locked(),
            TableKeys::derive(self.mk.locked())?,
        ))
    }

    /// Lock the profile: every key held here is dropped and its page zeroized.
    pub fn lock(self) {
        drop(self);
    }

    /// `MK_profile` (feature `kat`, ST-19).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub fn mk_kat(&self) -> &secmp_crypto::LockedSecret<32> {
        self.mk.locked()
    }

    /// SHA-256 of `MK_profile` (feature `kat`, ST-05).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub fn mk_digest_kat(&self) -> [u8; 32] {
        secmp_crypto::sha256(&[self.mk.locked().expose_secret()])
    }

    /// `K_db` (feature `kat`, ST-19).
    ///
    /// # Errors
    /// As [`Unlocked::db_key`].
    #[cfg(any(test, feature = "kat"))]
    pub fn db_kat(&self) -> Result<StoreKey> {
        derive(self.mk.locked(), Label::StoreDb)
    }

    /// The key of `table` (feature `kat`, ST-19).
    ///
    /// # Errors
    /// As [`Unlocked::db_key`].
    #[cfg(any(test, feature = "kat"))]
    pub fn table_key_kat(&self, table: crate::keys::Table) -> Result<StoreKey> {
        derive(self.mk.locked(), table.label())
    }
}

/// The wrap of `mk` under `passphrase` with a fresh salt and nonce (ADR-053 item 2).
fn seal(mk: &StoreKey, passphrase: &[u8], params: Argon2Params) -> Result<Vec<u8>> {
    let salt = crate::rand::public::<16>()?;
    let enc = params.encode();
    let kek = kek(passphrase, &salt, params)?;
    let nonce = crate::rand::nonce()?;
    let n = *nonce.as_bytes();
    // spec §3.4; ADR-053 item 2
    let sealed = Caead::seal_locked(
        kek.locked(),
        nonce,
        &ad(&salt, &enc),
        mk.locked().expose_secret(),
    )
    .map_err(|_| Error::Unavailable)?;
    let wrap = [&[VER][..], &salt, &enc, &n, &sealed].concat();
    if wrap.len() == WRAP_LEN {
        Ok(wrap)
    } else {
        Err(Error::Unavailable)
    }
}

/// Create the wrap of a new profile in `dir` (a fresh `MK_profile`, [`Argon2Params::PROFILE`]).
///
/// # Errors
/// [`Error::Unavailable`] if `dir` already holds a wrap, randomness or locked memory is unavailable, or the file cannot be
/// written.
pub fn create(dir: &Path, passphrase: &[u8]) -> Result<Unlocked> {
    create_with(dir, passphrase, Argon2Params::PROFILE)
}

/// [`create`] with `params` (feature `kat`: the small parameters of the test rows).
///
/// # Errors
/// As [`create`].
#[cfg(any(test, feature = "kat"))]
pub fn create_kat(dir: &Path, passphrase: &[u8], params: Argon2Params) -> Result<Unlocked> {
    create_with(dir, passphrase, params)
}

fn create_with(dir: &Path, passphrase: &[u8], params: Argon2Params) -> Result<Unlocked> {
    std::fs::create_dir_all(dir).map_err(|_| Error::Unavailable)?;
    let path = dir.join(WRAP_FILE);
    if path.exists() {
        return Err(Error::Unavailable);
    }
    let mk = crate::rand::key()?;
    let wrap = seal(&mk, passphrase, params)?;
    let tmp = dir.join("wrap.tmp");
    std::fs::write(&tmp, &wrap).map_err(|_| Error::Unavailable)?;
    std::fs::rename(&tmp, &path).map_err(|_| Error::Unavailable)?;
    Ok(Unlocked::from_mk(mk))
}

/// Unlock the profile in `dir` with `passphrase` (accepts [`Argon2Params::PROFILE`] only).
///
/// # Errors
/// [`Error::Unlock`] for a wrong passphrase or any wrap that is not a profile wrap (uniform); [`Error::Unavailable`] if
/// the file cannot be read.
pub fn unlock(dir: &Path, passphrase: &[u8]) -> Result<Unlocked> {
    let wrap = std::fs::read(dir.join(WRAP_FILE)).map_err(|_| Error::Unavailable)?;
    open(&wrap, passphrase, Argon2Params::PROFILE)
}

/// [`unlock`] accepting `accept` instead of the profile parameters (feature `kat`).
///
/// # Errors
/// As [`unlock`].
#[cfg(any(test, feature = "kat"))]
pub fn unlock_kat(dir: &Path, passphrase: &[u8], accept: Argon2Params) -> Result<Unlocked> {
    let wrap = std::fs::read(dir.join(WRAP_FILE)).map_err(|_| Error::Unavailable)?;
    open(&wrap, passphrase, accept)
}

/// Open the wrap bytes `wrap` (no file access) accepting `accept` (feature `kat`: the constant-time target, the
/// small-parameter rows).
///
/// # Errors
/// As [`unlock`].
#[cfg(any(test, feature = "kat"))]
pub fn open_kat(wrap: &[u8], passphrase: &[u8], accept: Argon2Params) -> Result<Unlocked> {
    open(wrap, passphrase, accept)
}

/// The `KEK` of `passphrase` over `salt` (feature `kat`, ST-19).
///
/// # Errors
/// As the KDF of [`unlock`].
#[cfg(any(test, feature = "kat"))]
pub fn kek_kat(passphrase: &[u8], salt: &[u8; 16], params: Argon2Params) -> Result<StoreKey> {
    kek(passphrase, salt, params)
}

/// ADR-053 item 2, the unlock order: file bytes checked, then Argon2id once, then `CAEAD.Open` once.
fn open(wrap: &[u8], passphrase: &[u8], accept: Argon2Params) -> Result<Unlocked> {
    // decided from the file bytes alone, before the KDF (Q123)
    if wrap.len() != WRAP_LEN {
        return Err(Error::Unlock);
    }
    let (head, rest) = wrap.split_at_checked(29).ok_or(Error::Unlock)?;
    let (n, sealed) = rest.split_at_checked(24).ok_or(Error::Unlock)?;
    let (ver, tail) = head.split_at_checked(1).ok_or(Error::Unlock)?;
    let (salt, params) = tail.split_at_checked(16).ok_or(Error::Unlock)?;
    if ver != [VER] || params != accept.encode() {
        return Err(Error::Unlock);
    }
    let salt: [u8; 16] = salt.try_into().map_err(|_| Error::Unlock)?;
    let enc: [u8; 12] = params.try_into().map_err(|_| Error::Unlock)?;
    let n: [u8; 24] = n.try_into().map_err(|_| Error::Unlock)?;
    let kek = kek(passphrase, &salt, accept)?;
    #[cfg(any(test, feature = "kat"))]
    crate::kat::note_caead_open_call();
    // spec §3.4; ADR-053 item 2
    let mk = Caead::open_locked(kek.locked(), &n, &ad(&salt, &enc), sealed)
        .map_err(|_| Error::Unlock)?;
    let mk = StoreKey::new(secmp_crypto::LockedSecret::from_slice(&mk).map_err(|_| Error::Unlock)?);
    Ok(Unlocked::from_mk(mk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::TempDir;
    #[cfg(feature = "kat")]
    use crate::kat::{argon2_calls, caead_open_calls, reset_counters};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;

    const PASS: &[u8] = b"correct horse battery staple";

    /// A `kat_small` wrap of a fresh profile in `dir`, and its bytes.
    #[cfg(feature = "kat")]
    fn small_wrap(
        dir: &Path,
    ) -> core::result::Result<(Unlocked, Vec<u8>), Box<dyn std::error::Error>> {
        let u = create_kat(dir, PASS, Argon2Params::kat_small())?;
        let bytes = std::fs::read(dir.join(WRAP_FILE))?;
        Ok((u, bytes))
    }

    /// ST-05 (CS-3.2; ADR-053 items 1, 2): a profile created with P unlocks with P (the same `MK_profile`, by its digest)
    /// and not with P's last byte flipped.
    #[test]
    #[cfg(feature = "kat")]
    fn unlock_roundtrip() -> R {
        let dir = TempDir::new("st05")?;
        let (created, bytes) = small_wrap(dir.path())?;
        assert_eq!(bytes.len(), WRAP_LEN);
        let again = unlock_kat(dir.path(), PASS, Argon2Params::kat_small())?;
        assert_eq!(again.mk_digest_kat(), created.mk_digest_kat());
        let mut flipped = PASS.to_vec();
        if let Some(last) = flipped.last_mut() {
            *last ^= 1;
        }
        assert_eq!(
            unlock_kat(dir.path(), &flipped, Argon2Params::kat_small()).err(),
            Some(Error::Unlock)
        );
        Ok(())
    }

    /// The eight ST-06 cases: (name, the wrap bytes, the passphrase, through shipped `unlock`?).
    #[cfg(feature = "kat")]
    fn st06_cases(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>, Vec<u8>, bool)> {
        let flip = |at: usize| {
            let mut b = bytes.to_vec();
            if let Some(x) = b.get_mut(at) {
                *x ^= 1;
            }
            b
        };
        let with_params = |p: Argon2Params| {
            let mut b = bytes.to_vec();
            if let Some(dst) = b.get_mut(17..29) {
                dst.copy_from_slice(&p.encode());
            }
            b
        };
        vec![
            ("wrong passphrase", bytes.to_vec(), b"wrong".to_vec(), false),
            (
                "truncated",
                bytes.get(..132).unwrap_or_default().to_vec(),
                PASS.to_vec(),
                false,
            ),
            ("flipped salt", flip(5), PASS.to_vec(), false),
            ("flipped tag", flip(WRAP_LEN - 1), PASS.to_vec(), false),
            ("wrong version", flip(0), PASS.to_vec(), true),
            (
                "params m = 4 194 304 KiB",
                with_params(Argon2Params {
                    m_kib: 4_194_304,
                    t: 3,
                    p: 4,
                }),
                PASS.to_vec(),
                true,
            ),
            (
                "params t = 4",
                with_params(Argon2Params {
                    m_kib: 262_144,
                    t: 4,
                    p: 4,
                }),
                PASS.to_vec(),
                true,
            ),
            (
                "params p = 1",
                with_params(Argon2Params {
                    m_kib: 262_144,
                    t: 3,
                    p: 1,
                }),
                PASS.to_vec(),
                true,
            ),
        ]
    }

    /// ST-06 (Q123; ADR-053 item 2; CLAUDE.md §4): a wrong passphrase, a truncated wrap, a flipped salt, a flipped tag, a
    /// wrong version byte and three `params` other than `PROFILE` all give the one `Error::Unlock` (equal values, equal
    /// `Debug` strings, no field); the version and the three `params` cases go through the shipped `unlock` and are
    /// rejected from the file bytes, before any KDF work (`argon2_calls` = 0).
    #[test]
    #[cfg(feature = "kat")]
    fn unlock_errors_are_uniform() -> R {
        let dir = TempDir::new("st06")?;
        let (_u, bytes) = small_wrap(dir.path())?;
        let mut seen = Vec::new();
        for (name, wrap, pass, shipped) in st06_cases(&bytes) {
            reset_counters();
            let err = if shipped {
                let case_dir = TempDir::new("st06-case")?;
                std::fs::write(case_dir.path().join(WRAP_FILE), &wrap)?;
                unlock(case_dir.path(), &pass).err()
            } else {
                open_kat(&wrap, &pass, Argon2Params::kat_small()).err()
            };
            assert_eq!(err, Some(Error::Unlock), "{name}");
            if shipped {
                assert_eq!(argon2_calls(), 0, "{name}: decided before the KDF");
            }
            seen.push(format!("{err:?}"));
        }
        assert_eq!(seen.len(), 8);
        assert!(seen.iter().all(|s| s == "Some(Unlock)"), "{seen:?}");
        Ok(())
    }

    /// Extra (A-4 §3): the error text of every ST-06 case is the fixed text, and no source file of the store formats an
    /// error or a value with `{e}`, `{e:?}`, `{:?}` or `.to_string()` outside its tests (vet N-3/N-4: no rusqlite text).
    #[test]
    #[cfg(feature = "kat")]
    fn unlock_error_text_is_fixed() -> R {
        let dir = TempDir::new("st06-text")?;
        let (_u, bytes) = small_wrap(dir.path())?;
        for (name, wrap, pass, _) in st06_cases(&bytes) {
            let err = open_kat(&wrap, &pass, Argon2Params::kat_small())
                .err()
                .ok_or(name)?;
            assert_eq!(
                err.to_string(),
                "secmp-store: the profile could not be unlocked",
                "{name}"
            );
        }
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut hits = Vec::new();
        for entry in std::fs::read_dir(&src_dir)? {
            let path = entry?.path();
            let text = std::fs::read_to_string(&path)?.replace("\r\n", "\n");
            let product = text
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            for needle in ["{e}", "{e:?}", "{:?}", ".to_string()"] {
                if product.contains(needle) {
                    hits.push(format!("{}: {needle}", path.display()));
                }
            }
        }
        assert_eq!(hits, Vec::<String>::new());
        Ok(())
    }

    /// ST-07 (CS-3.2; ADR-053 item 1): the shipped parameters are Argon2id v0x13, m = 262 144 KiB, t = 3, p = 4, with a
    /// 16-byte salt and a 32-byte output, and one `PROFILE` wrap carries `00 04 00 00 00 00 00 03 00 00 00 04` at offset
    /// 17..29 (its time is in the report).
    #[test]
    fn argon2_params_are_cs_3_2() -> R {
        assert_eq!(
            Argon2Params::PROFILE,
            Argon2Params {
                m_kib: 262_144,
                t: 3,
                p: 4
            }
        );
        assert_eq!(
            Argon2Params::PROFILE.encode(),
            [0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4]
        );
        let dir = TempDir::new("st07")?;
        let started = std::time::Instant::now();
        let u = create(dir.path(), PASS)?;
        let created_ms = started.elapsed().as_millis();
        let bytes = std::fs::read(dir.path().join(WRAP_FILE))?;
        assert_eq!(bytes.len(), WRAP_LEN);
        assert_eq!(bytes.first(), Some(&0x01));
        assert_eq!(
            bytes.get(17..29),
            Some([0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4].as_slice())
        );
        let again = unlock(dir.path(), PASS)?;
        assert_eq!(again.mk_digest_kat(), u.mk_digest_kat());
        // the salt is 16 bytes (offset 1..17) and the output 32 bytes (the key types)
        assert_eq!(bytes.get(1..17).map(<[u8]>::len), Some(16));
        let _: &secmp_crypto::LockedSecret<32> = u.mk_kat();
        std::fs::write(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/m7-st07-time.txt"),
            format!(
                "ST-07 PROFILE wrap: create {created_ms} ms (one Argon2id m = 256 MiB, t = 3, p = 4)\n"
            ),
        )?;
        Ok(())
    }

    /// CT-02 (OPEN-M7-15; ADR-053 item 2): the right, a wrong, the empty, a prefix-sharing and a one-byte-longer
    /// passphrase each cost exactly one Argon2id and one `CAEAD.Open`; the four failures are the one `Error::Unlock`.
    #[test]
    #[cfg(feature = "kat")]
    fn unlock_work_is_outcome_independent() -> R {
        let dir = TempDir::new("ct02")?;
        let (_u, bytes) = small_wrap(dir.path())?;
        let longer = [PASS, b"!"].concat();
        let cases: [(&str, &[u8]); 5] = [
            ("right", PASS),
            ("wrong", b"another phrase entirely"),
            ("empty", b""),
            ("prefix-sharing", b"correct horse"),
            ("one byte longer", &longer),
        ];
        for (name, pass) in cases {
            reset_counters();
            let out = open_kat(&bytes, pass, Argon2Params::kat_small());
            assert_eq!((argon2_calls(), caead_open_calls()), (1, 1), "{name}");
            if name == "right" {
                assert!(out.is_ok());
            } else {
                assert_eq!(out.err(), Some(Error::Unlock), "{name}");
            }
        }
        Ok(())
    }
}
