// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's keys (spec §8.2, §9.6; `docs/05` §6 runbook): the key file, `keygen`, `rotate-static`, and the
//! [`KeyRing`] the server answers with.
//!
//! **Key file** (local, never on the wire; written only by `keygen` and `rotate-static`, read once at start):
//!
//! ```text
//! "SMPRKEYS" ‖ ver 0x01 ‖ relay_sig seed[32] ‖ relay_access_key[32] ‖ count u8 (1..=8) ‖
//!     { kid u32 ‖ valid_until u64 ‖ relay_dh secret[32] ‖ relay_kem seed[64] } × count
//! ```
//!
//! big-endian, exact fit; the generations in strictly ascending `kid` with non-decreasing `valid_until`, so that the
//! generations still valid at any time are a suffix of the list. Every secret is read into and kept in zeroizing
//! memory (`SecretBytes`, the locked pages of the key types).
//!
//! **Rotation** (OPEN-M5-10 A): `RELAYINFO` announces the newest generation; `HS1` is accepted for any held
//! generation whose `valid_until ≥ now`; a generation is dropped after its `valid_until`; `rotate-static` adds
//! `kid + 1` with `valid_until ≤ now + 5 184 000` (the 60-day bound of §8.2) and keeps `relay_sig`, so `relay_fp` is
//! stable.

use std::path::Path;

use secmp_crypto::{
    Ed25519SigningKey, MlKem1024Dk, SecretBytes, X25519Secret, ZeroizeOnDrop, Zeroizing,
};
use secmp_proto::link::MAX_VALIDITY_SECS;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;

use crate::error::{Error, Result};

/// The magic of the key file.
const MAGIC: &[u8; 8] = b"SMPRKEYS";
/// The key file version.
const VERSION: u8 = 0x01;
/// The most generations a key file holds.
pub const MAX_GENERATIONS: usize = 8;
/// The default validity of a new generation: 45 days (`docs/05` §5 `relayinfo_valid_days`).
pub const DEFAULT_VALIDITY_SECS: u64 = 3_888_000;
/// Bytes of one generation record.
const GENERATION_LEN: usize = 4 + 8 + 32 + 64;

/// One key generation as stored.
pub struct Generation {
    /// The generation.
    pub kid: u32,
    /// Unix seconds; `HS1` naming this generation is accepted while `valid_until ≥ now`.
    pub valid_until: u64,
    dh: SecretBytes<32>,
    kem: SecretBytes<64>,
}

impl ZeroizeOnDrop for Generation {}

/// The contents of a key file.
pub struct KeyFile {
    sig: SecretBytes<32>,
    access: SecretBytes<32>,
    generations: Vec<Generation>,
}

impl ZeroizeOnDrop for KeyFile {}

fn secret<const N: usize>(b: &[u8]) -> Result<SecretBytes<N>> {
    SecretBytes::from_slice(b).map_err(|_| Error::KeyFile)
}

fn check_validity(validity_secs: u64) -> Result<()> {
    if validity_secs == 0 || validity_secs > MAX_VALIDITY_SECS {
        return Err(Error::Config("validity must be 1 s to 60 days (spec §8.2)"));
    }
    Ok(())
}

impl KeyFile {
    /// `keygen` (`docs/05` §6): a new identity from the OS source — `relay_sig`, the access key and generation
    /// `kid` 1 valid for `validity_secs` from `now_unix`.
    ///
    /// # Errors
    /// [`Error::Config`] for a validity of 0 or beyond 60 days; [`Error::Unavailable`] without randomness.
    pub fn generate(now_unix: u64, validity_secs: u64) -> Result<Self> {
        check_validity(validity_secs)?;
        let mut file = Self {
            sig: SecretBytes::random().map_err(|_| Error::Unavailable)?,
            access: SecretBytes::random().map_err(|_| Error::Unavailable)?,
            generations: Vec::new(),
        };
        file.push_generation(1, now_unix, validity_secs)?;
        Ok(file)
    }

    fn push_generation(&mut self, kid: u32, now_unix: u64, validity_secs: u64) -> Result<()> {
        let valid_until = now_unix
            .checked_add(validity_secs)
            .ok_or(Error::Config("valid_until overflows"))?;
        self.generations.push(Generation {
            kid,
            valid_until,
            dh: SecretBytes::random().map_err(|_| Error::Unavailable)?,
            kem: SecretBytes::random().map_err(|_| Error::Unavailable)?,
        });
        Ok(())
    }

    /// `rotate-static` (`docs/05` §6, OPEN-M5-10): drop the generations expired at `now_unix`, then add `kid + 1`
    /// of the newest one, valid for `validity_secs`; `relay_sig` and the access key stay. Returns the new `kid`.
    ///
    /// # Errors
    /// [`Error::Config`] for a validity of 0 or beyond 60 days, a `kid` that would overflow, a `valid_until` that
    /// would fall before the newest held one, or a ring already at [`MAX_GENERATIONS`]; [`Error::Unavailable`]
    /// without randomness.
    pub fn rotate(&mut self, now_unix: u64, validity_secs: u64) -> Result<u32> {
        check_validity(validity_secs)?;
        let newest = self.generations.last().ok_or(Error::KeyFile)?;
        let kid = newest
            .kid
            .checked_add(1)
            .ok_or(Error::Config("kid exhausted"))?;
        let newest_until = newest.valid_until;
        if now_unix.saturating_add(validity_secs) < newest_until {
            return Err(Error::Config(
                "a new generation must not expire before the newest one",
            ));
        }
        self.generations.retain(|g| g.valid_until >= now_unix);
        if self.generations.len() >= MAX_GENERATIONS {
            return Err(Error::Config("too many key generations"));
        }
        self.push_generation(kid, now_unix, validity_secs)?;
        Ok(kid)
    }

    /// The generations.
    #[must_use]
    pub fn generations(&self) -> &[Generation] {
        &self.generations
    }

    /// The file bytes.
    ///
    /// # Errors
    /// [`Error::KeyFile`] if the contents break the file rules (not reachable for a generated file).
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let count = u8::try_from(self.generations.len()).map_err(|_| Error::KeyFile)?;
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(self.sig.expose_secret());
        out.extend_from_slice(self.access.expose_secret());
        out.push(count);
        for g in &self.generations {
            out.extend_from_slice(&g.kid.to_be_bytes());
            out.extend_from_slice(&g.valid_until.to_be_bytes());
            out.extend_from_slice(g.dh.expose_secret());
            out.extend_from_slice(g.kem.expose_secret());
        }
        // round trip through the decoder: never write a file the relay would refuse
        Self::decode(&out)?;
        Ok(out)
    }

    /// Parse key-file bytes (exact fit; the rules of the module documentation).
    ///
    /// # Errors
    /// [`Error::KeyFile`] on any violation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let rest = bytes.strip_prefix(MAGIC.as_slice()).ok_or(Error::KeyFile)?;
        let (&ver, rest) = rest.split_first().ok_or(Error::KeyFile)?;
        if ver != VERSION {
            return Err(Error::KeyFile);
        }
        let (sig, rest) = rest.split_first_chunk::<32>().ok_or(Error::KeyFile)?;
        let (access, rest) = rest.split_first_chunk::<32>().ok_or(Error::KeyFile)?;
        let (&count, mut rest) = rest.split_first().ok_or(Error::KeyFile)?;
        let count = usize::from(count);
        if count == 0 || count > MAX_GENERATIONS {
            return Err(Error::KeyFile);
        }
        let mut generations: Vec<Generation> = Vec::with_capacity(count);
        for _ in 0..count {
            let (record, tail) = rest
                .split_first_chunk::<GENERATION_LEN>()
                .ok_or(Error::KeyFile)?;
            rest = tail;
            let (kid, r) = record.split_first_chunk::<4>().ok_or(Error::KeyFile)?;
            let (until, r) = r.split_first_chunk::<8>().ok_or(Error::KeyFile)?;
            let (dh, kem) = r.split_first_chunk::<32>().ok_or(Error::KeyFile)?;
            let g = Generation {
                kid: u32::from_be_bytes(*kid),
                valid_until: u64::from_be_bytes(*until),
                dh: secret(dh)?,
                kem: secret(kem)?,
            };
            if let Some(prev) = generations.last()
                && (g.kid <= prev.kid || g.valid_until < prev.valid_until)
            {
                return Err(Error::KeyFile);
            }
            generations.push(g);
        }
        if !rest.is_empty() {
            return Err(Error::KeyFile);
        }
        Ok(Self {
            sig: secret(sig)?,
            access: secret(access)?,
            generations,
        })
    }

    /// Read and parse a key file.
    ///
    /// # Errors
    /// [`Error::KeyFile`] if it is missing, unreadable or malformed.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| Error::KeyFile)?);
        Self::decode(&bytes)
    }

    /// Write a new key file at `path` (`keygen`); an existing file is never overwritten. Mode 0600 on Unix.
    ///
    /// # Errors
    /// [`Error::Io`] if the file exists or cannot be written.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        write_file(path, &self.encode()?)
    }

    /// Replace the key file at `path` (`rotate-static`): written next to it, then renamed over it.
    ///
    /// # Errors
    /// [`Error::Io`] if the temporary file exists or a step fails.
    pub fn replace(&self, path: &Path) -> Result<()> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".new");
        let tmp = std::path::PathBuf::from(tmp);
        write_file(&tmp, &self.encode()?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// The relay keys of every generation, for the server.
    ///
    /// # Errors
    /// [`Error::KeyFile`] if a key is refused; [`Error::Unavailable`] without locked memory.
    pub fn ring(&self) -> Result<KeyRing> {
        let mut keys = Vec::with_capacity(self.generations.len());
        for g in &self.generations {
            let sig = Ed25519SigningKey::from_seed(self.sig.expose_secret())
                .map_err(|_| Error::Unavailable)?;
            let dh =
                X25519Secret::from_bytes(g.dh.expose_secret()).map_err(|_| Error::Unavailable)?;
            let kem =
                MlKem1024Dk::from_seed(g.kem.expose_secret()).map_err(|_| Error::Unavailable)?;
            let access: AccessKey =
                SecretBytes::from_slice(self.access.expose_secret()).map_err(|_| Error::KeyFile)?;
            let k = RelayKeys::new(sig, dh, kem, access, g.kid).map_err(|_| Error::KeyFile)?;
            keys.push((k, g.valid_until));
        }
        KeyRing::new(keys)
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// The key generations the relay holds (ascending `kid`, non-decreasing `valid_until`; spec §8.2).
pub struct KeyRing {
    keys: Vec<RelayKeys>,
    valid_until: Vec<u64>,
}

impl KeyRing {
    /// A ring from `(keys, valid_until)` pairs.
    ///
    /// # Errors
    /// [`Error::KeyFile`] if empty, not in ascending `kid`, with a decreasing `valid_until`, or not of one identity
    /// (`relay_sig` and access key).
    pub fn new(generations: Vec<(RelayKeys, u64)>) -> Result<Self> {
        let first = generations.first().ok_or(Error::KeyFile)?;
        let (sig_pk, akc) = (*first.0.sig_pk(), first.0.akc());
        for pair in generations.windows(2) {
            if let [(a, ua), (b, ub)] = pair
                && (b.kid() <= a.kid() || ub < ua)
            {
                return Err(Error::KeyFile);
            }
        }
        if generations
            .iter()
            .any(|(k, _)| *k.sig_pk() != sig_pk || k.akc() != akc)
        {
            return Err(Error::KeyFile);
        }
        let (keys, valid_until) = generations.into_iter().unzip();
        Ok(Self { keys, valid_until })
    }

    /// The keys, ascending `kid` (`secmp_proto::link::relay::accept_ring`).
    #[must_use]
    pub fn ring(&self) -> &[RelayKeys] {
        &self.keys
    }

    /// The newest generation and its `valid_until` (what `RELAYINFO` announces).
    ///
    /// # Errors
    /// None in practice (a ring is never empty).
    pub fn newest(&self) -> Result<(&RelayKeys, u64)> {
        match (self.keys.last(), self.valid_until.last()) {
            (Some(k), Some(u)) => Ok((k, *u)),
            _ => Err(Error::KeyFile),
        }
    }

    /// Whether `HS1` naming `kid` is accepted at `now_unix`: the generation is held and `valid_until ≥ now`.
    #[must_use]
    pub fn usable(&self, kid: u32, now_unix: u64) -> bool {
        self.keys
            .iter()
            .zip(&self.valid_until)
            .any(|(k, &u)| k.kid() == kid && u >= now_unix)
    }

    /// The `kid`s held, ascending.
    #[must_use]
    pub fn kids(&self) -> Vec<u32> {
        self.keys.iter().map(RelayKeys::kid).collect()
    }

    /// The access key (spec §9.6), the same in every generation.
    ///
    /// # Errors
    /// None in practice (a ring is never empty).
    pub fn access_key(&self) -> Result<&AccessKey> {
        self.keys
            .first()
            .map(RelayKeys::access_key)
            .ok_or(Error::KeyFile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_100;

    #[test]
    fn a_generated_file_round_trips() -> Result<()> {
        let f = KeyFile::generate(NOW, DEFAULT_VALIDITY_SECS)?;
        let bytes = f.encode()?;
        assert_eq!(bytes.len(), 8 + 1 + 32 + 32 + 1 + GENERATION_LEN);
        let g = KeyFile::decode(&bytes)?;
        assert_eq!(g.encode()?.as_slice(), bytes.as_slice());
        assert_eq!(g.generations().len(), 1);
        let gen1 = g.generations().first().ok_or(Error::KeyFile)?;
        assert_eq!(gen1.kid, 1);
        assert_eq!(gen1.valid_until, NOW + DEFAULT_VALIDITY_SECS);
        Ok(())
    }

    #[test]
    fn the_decoder_refuses_every_rule_violation() -> Result<()> {
        let f = KeyFile::generate(NOW, DEFAULT_VALIDITY_SECS)?;
        let good = f.encode()?.to_vec();
        let mut bad: Vec<Vec<u8>> = Vec::new();
        bad.push(Vec::new());
        bad.push(
            good.get(..good.len().saturating_sub(1))
                .unwrap_or_default()
                .to_vec(),
        );
        bad.push([good.as_slice(), &[0]].concat());
        let mut v = good.clone();
        if let Some(b) = v.get_mut(0) {
            *b ^= 1;
        }
        bad.push(v);
        let mut v = good.clone();
        if let Some(b) = v.get_mut(8) {
            *b = 2;
        }
        bad.push(v);
        for count in [0_u8, 2, 9] {
            let mut v = good.clone();
            if let Some(b) = v.get_mut(8 + 1 + 64) {
                *b = count;
            }
            bad.push(v);
        }
        for b in &bad {
            assert!(KeyFile::decode(b).is_err());
        }
        Ok(())
    }

    /// Raw key-file bytes with the given (`kid`, `valid_until`) generations and the announced `count`.
    fn raw_file(count: u8, generations: &[(u32, u64)]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.extend_from_slice(&[1; 32]);
        out.extend_from_slice(&[2; 32]);
        out.push(count);
        for &(kid, until) in generations {
            out.extend_from_slice(&kid.to_be_bytes());
            out.extend_from_slice(&until.to_be_bytes());
            out.extend_from_slice(&[3; 32]);
            out.extend_from_slice(&[4; 64]);
        }
        out
    }

    fn generations_of(n: u32) -> Vec<(u32, u64)> {
        (1..=n).map(|k| (k, NOW + u64::from(k))).collect()
    }

    #[test]
    fn the_decoder_bounds_and_orders_the_generations() -> Result<()> {
        // 1 to MAX_GENERATIONS generations are a file; 0 and 9 are not, whatever follows the count
        assert_eq!(
            KeyFile::decode(&raw_file(1, &generations_of(1)))?
                .generations()
                .len(),
            1
        );
        assert_eq!(
            KeyFile::decode(&raw_file(8, &generations_of(8)))?
                .generations()
                .len(),
            8
        );
        assert!(KeyFile::decode(&raw_file(0, &[])).is_err());
        assert!(KeyFile::decode(&raw_file(9, &generations_of(9))).is_err());
        // ascending kid, non-decreasing valid_until; an equal valid_until is fine
        let ok = KeyFile::decode(&raw_file(2, &[(1, NOW), (2, NOW)]))?;
        assert_eq!(
            ok.generations().iter().map(|g| g.kid).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(KeyFile::decode(&raw_file(2, &[(1, NOW), (3, NOW + 1)])).is_ok());
        for bad in [
            [(2, NOW), (2, NOW + 1)],
            [(3, NOW), (2, NOW + 1)],
            [(1, NOW + 1), (2, NOW)],
        ] {
            assert!(KeyFile::decode(&raw_file(2, &bad)).is_err(), "{bad:?}");
        }
        // the announced count must match the records exactly
        assert!(KeyFile::decode(&raw_file(1, &generations_of(2))).is_err());
        assert!(KeyFile::decode(&raw_file(2, &generations_of(1))).is_err());
        Ok(())
    }

    #[test]
    fn rotation_adds_the_next_kid_and_keeps_the_identity() -> Result<()> {
        let mut f = KeyFile::generate(NOW, DEFAULT_VALIDITY_SECS)?;
        let before = f.ring()?;
        assert_eq!(f.rotate(NOW + 100, DEFAULT_VALIDITY_SECS)?, 2);
        let ring = f.ring()?;
        assert_eq!(ring.kids(), vec![1, 2]);
        let (newest, until) = ring.newest()?;
        assert_eq!(newest.kid(), 2);
        assert_eq!(until, NOW + 100 + DEFAULT_VALIDITY_SECS);
        assert_eq!(newest.fp(), before.newest()?.0.fp());
        assert!(ring.usable(1, NOW + DEFAULT_VALIDITY_SECS));
        assert!(!ring.usable(1, NOW + DEFAULT_VALIDITY_SECS + 1));
        assert!(ring.usable(2, NOW + DEFAULT_VALIDITY_SECS + 1));
        assert!(!ring.usable(3, NOW));
        // after its valid_until the old generation is dropped by the next rotation
        assert_eq!(
            f.rotate(NOW + DEFAULT_VALIDITY_SECS + 1, DEFAULT_VALIDITY_SECS)?,
            3
        );
        assert_eq!(f.ring()?.kids(), vec![2, 3]);
        assert!(f.rotate(NOW, MAX_VALIDITY_SECS + 1).is_err());
        assert!(f.rotate(NOW, 0).is_err());
        Ok(())
    }

    /// M5-C carry-over (run 37851301032, `keys.rs:120:51`): a new generation that expires exactly when the newest one
    /// does is accepted; one second earlier is the `Config` error, and a refused rotation changes nothing.
    #[test]
    fn rotation_boundary_new_generation_may_expire_with_the_newest() -> Result<()> {
        let mut f = KeyFile::generate(NOW, DEFAULT_VALIDITY_SECS)?;
        let newest_until = NOW + DEFAULT_VALIDITY_SECS;
        let now = NOW + 100;
        let early = f.rotate(now, newest_until - now - 1);
        assert!(matches!(early, Err(Error::Config(_))), "one second short");
        assert_eq!(f.generations().len(), 1, "nothing added");
        assert_eq!(f.rotate(now, newest_until - now)?, 2, "exactly equal");
        assert_eq!(f.ring()?.newest()?.1, newest_until);
        Ok(())
    }
}
