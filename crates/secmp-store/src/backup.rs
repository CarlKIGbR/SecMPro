// SPDX-License-Identifier: AGPL-3.0-or-later
//! The backup export and import (CS-3.5 `docs/04:55`; ADR-053 item 6 and Appendix):
//!
//! ```text
//! file    = "SecMProbackup" ‖ header ‖ N(24) ‖ CAEAD.Seal(K_bk, N, AD = "SecMP-STORE/1 backup" ‖ header, body)
//! header  = ver(0x01) ‖ salt(16) ‖ params(12) ‖ bwrap ‖ section table                                  (154 B)
//! bwrap   = N'(24) ‖ CAEAD.Seal(KEK_bk, N', AD = "SecMP-STORE/1 bwrap" ‖ ver ‖ salt ‖ params, MK_bk)  (104 B)
//! KEK_bk  = Argon2id over the backup passphrase and salt (ADR-053 item 1); MK_bk fresh 32 B
//! K_bk    = HKDF-SHA-256(salt = 0^32, IKM = MK_bk, info = "SecMP-STORE/1 backup", L = 32)
//! section table = count u8 (= 4) ‖ {tag u8 ‖ len u32} × 4, tags 1 identity, 2 contacts, 3 settings, 4 messages
//! ```
//!
//! `body` is the four sections concatenated, each exactly `len` bytes (Appendix): identity = the 97-byte identity
//! section (`ver ‖ ed25519_seed ‖ mldsa65_seed ‖ x25519_secret`, the plaintext of `identity.secret`, Q143); contacts =
//! `n u32 ‖ {IKSPublic[2017] ‖ verified u8 ‖ Profile (D.3) ‖ local_name_len u8 ‖ local_name} × n`; settings =
//! `n u16 ‖ {key_len u8 ‖ key ‖ val_len u16 ‖ val} × n`; messages = `n u32 ‖ {contact_index u32 ‖ direction u8 ‖ ts u64 ‖
//! AppMessage (D.5)} × n`, no view-once (CS-3.4, Q125). Nothing else: no ratchet state, no prekey, no outbox, no relay,
//! no invitation (CS-3.5) — a restored contact must be re-invited (Q142). The backup passphrase is its own (Q124); the
//! random inputs are drawn in the order salt, `MK_bk`, `N'`, `N`.
//!
//! **Open** decides from the file bytes alone, before any KDF work, that the magic, `ver`, `params` (item 2's acceptance
//! rule), the section table (four entries, tags 1–4 in order) and the total length are right; then Argon2id once, the
//! `bwrap` open, the body open, and the decoding of the four sections, each consuming exactly its `len`. Every failure
//! is the one [`Error::Unlock`] (no "bad length" vs "bad tag", CLAUDE.md §4; Q125). Import writes nothing unless all of
//! it decoded.
//!
//! **Export** happens only on the user's explicit request (CS-3.5: never automatic — no timer, no startup path; the one
//! caller is the client's `Api` handler, Phase B): [`export`] refuses without `confirm` ([`Error::ConfirmRequired`],
//! whose text is the warning the user confirms) and refuses a path inside a cloud-synchronised folder
//! ([`Error::CloudFolder`], [`CLOUD_FOLDERS`]) unless `force`.

use std::io::Write as _;
use std::path::Path;

use rusqlite::params;
use secmp_crypto::{Caead, HybridSigningKey, Label, LockedSecret, Zeroizing};
use secmp_proto::prekeys::{IdentityKeys, IkDhSecret, fingerprint_of};
use secmp_proto::wire::cell::AppMessage;
use secmp_proto::wire::inv::{IksPublic, Profile};
use secmp_proto::{Decode, Encode};

use crate::contacts::{Contact, STATE_REINVITE_REQUIRED, put_contact};
use crate::error::{Error, Result};
use crate::keys::derive;
use crate::messages::{Direction, KIND_VIEW_ONCE};
use crate::profile::put_identity;
use crate::store::Store;
use crate::wrap::{Argon2Params, kdf_error, kek};

/// The plaintext magic of a backup file (it reveals the file type only; ADR-053 item 6).
pub const MAGIC: &[u8; 13] = b"SecMProbackup";
/// The backup format byte.
const VER: u8 = 0x01;
/// `bwrap = N' ‖ COM ‖ MK_bk ‖ tag`.
pub const BWRAP_LEN: usize = 24 + 32 + 32 + 16;
/// `count ‖ {tag ‖ len u32} × 4`.
pub const SECTION_TABLE_LEN: usize = 1 + 4 * 5;
/// `ver ‖ salt ‖ params ‖ bwrap ‖ section table`.
pub const HEADER_LEN: usize = 1 + 16 + 12 + BWRAP_LEN + SECTION_TABLE_LEN;
/// The identity section: `ver ‖ ed25519_seed ‖ mldsa65_seed ‖ x25519_secret`.
pub const IDENTITY_LEN: usize = 1 + 32 + 32 + 32;
/// The section tags, in their order.
pub const TAGS: [u8; 4] = [1, 2, 3, 4];
/// The overhead of the file around the body: magic, header, `N`, `COM`, tag.
const FILE_OVERHEAD: usize = 13 + HEADER_LEN + 24 + 32 + 16;
const _: () = assert!(BWRAP_LEN == 104 && HEADER_LEN == 154 && IDENTITY_LEN == 97);
/// The longest local name (`docs/02:95`; ADR-053 Appendix).
const LOCAL_NAME_MAX: usize = 64;

/// The settings keys a backup carries (A4-1-04): the keys product code uses (`retention_days`, `messages.rs`). A key
/// of a later phase goes into exactly one of this list and [`BACKUP_SETTINGS_EXCLUDED`] (the pinned test refuses a key
/// in neither).
pub const BACKUP_SETTINGS_KEYS: &[&str] = &["retention_days"];
/// The settings keys that a backup never carries.
pub const BACKUP_SETTINGS_EXCLUDED: &[&str] = &[];

/// The cloud-synchronised folders (OPEN-M7-37 A, Q141): an export path with a component equal to one of these (or
/// starting with one and a space, `-` or `_`; [`in_cloud_folder`]), compared case-insensitively, is refused unless `force`.
pub const CLOUD_FOLDERS: &[&str] = &[
    "OneDrive",
    "Dropbox",
    "Google Drive",
    "GoogleDrive",
    "iCloudDrive",
    "iCloud Drive",
    "Mobile Documents",
    "Nextcloud",
    "ownCloud",
    "pCloud",
    "MEGA",
    "Box",
];

/// Whether `path` lies inside a folder of [`CLOUD_FOLDERS`]: a component equal to a listed name (case-insensitively) or
/// starting with it followed by a space, `-` or `_` (`OneDrive - Org`, `Dropbox_Team`; A4-1-05). A bare prefix is no hit
/// (`Boxes`). Purely lexical: no file-system access ([`export`] canonicalises the path first).
#[must_use]
pub fn in_cloud_folder(path: &Path) -> bool {
    path.components().any(|c| match c {
        std::path::Component::Normal(name) => name.to_str().is_some_and(|n| {
            CLOUD_FOLDERS.iter().any(|f| {
                n.eq_ignore_ascii_case(f)
                    || (n.get(..f.len()).is_some_and(|p| p.eq_ignore_ascii_case(f))
                        && n.get(f.len()..)
                            .and_then(|rest| rest.chars().next())
                            .is_some_and(|c| matches!(c, ' ' | '-' | '_')))
            })
        }),
        _ => false,
    })
}

/// Write the backup file of `store` to `path` under the backup `passphrase` ([`Argon2Params::PROFILE`]), on the user's
/// explicit request only (CS-3.5).
///
/// # Errors
/// [`Error::ConfirmRequired`] without `confirm`; [`Error::CloudFolder`] for a path inside a folder of
/// [`CLOUD_FOLDERS`] without `force` (both before any work); [`Error::Unavailable`] if the profile has no identity, a
/// value does not fit its field, or the file cannot be written.
pub fn export(
    store: &Store,
    path: &Path,
    passphrase: &[u8],
    confirm: bool,
    force: bool,
) -> Result<()> {
    export_checked(
        store,
        path,
        passphrase,
        (confirm, force),
        Argon2Params::PROFILE,
    )
}

/// [`export`] with `params`: the confirmation and the cloud-folder refusal, then the file.
fn export_checked(
    store: &Store,
    path: &Path,
    passphrase: &[u8],
    (confirm, force): (bool, bool),
    params: Argon2Params,
) -> Result<()> {
    if !confirm {
        return Err(Error::ConfirmRequired);
    }
    let target = resolved(path)?;
    if !force && in_cloud_folder(&target) {
        return Err(Error::CloudFolder);
    }
    // an existing file (or a link) is never overwritten: refused before the key derivation, and again at the creation
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(Error::Unavailable);
    }
    let bytes = export_bytes(store, passphrase, params)?;
    write_new(&target, &bytes)
}

/// `path` with its parent canonicalised (symbolic links and `..` resolved; a relative path against the current
/// directory), so that the cloud-folder check sees the folder the file will really be in.
fn resolved(path: &Path) -> Result<std::path::PathBuf> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or(Error::Unavailable)?;
    let parent = std::fs::canonicalize(parent).map_err(|_| Error::Unavailable)?;
    Ok(parent.join(name))
}

/// Create `path` (which must not exist; `0600` on Unix), write `bytes` and sync them to disk.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| Error::Unavailable)?;
    let done = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if done.is_err() {
        let _ = std::fs::remove_file(path);
        return Err(Error::Unavailable);
    }
    Ok(())
}

/// A restored contact.
pub struct BackupContact {
    /// The peer's `IKSPublic` (2017 B).
    pub iks: Vec<u8>,
    /// The verified flag.
    pub verified: bool,
    /// The peer's `Profile` (D.3 encoding).
    pub profile: Vec<u8>,
    /// The user's own name for the contact.
    pub local_name: String,
}

/// A restored message.
pub struct BackupMessage {
    /// The index of its contact in [`Contents::contacts`].
    pub contact_index: u32,
    /// In or out.
    pub direction: Direction,
    /// When (`ts_ms`; Q143).
    pub ts_ms: u64,
    /// Its `msg_id`.
    pub msg_id: [u8; 16],
    /// `AppMessage.kind` (never view-once).
    pub kind: u8,
    /// `AppMessage.expire_after`.
    pub expire_after: u32,
    /// `AppMessage.payload`.
    pub payload: Zeroizing<Vec<u8>>,
}

/// The contents of a backup: exactly the four sections of the Appendix.
pub struct Contents {
    /// The identity section (97 B).
    pub identity: Zeroizing<Vec<u8>>,
    /// The contacts.
    pub contacts: Vec<BackupContact>,
    /// The settings.
    pub settings: Vec<(String, Zeroizing<Vec<u8>>)>,
    /// The messages.
    pub messages: Vec<BackupMessage>,
}

fn len_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::Unavailable)
}

impl Contents {
    /// The contents of `store`: its identity, contacts, settings and messages (no view-once).
    fn of(store: &Store) -> Result<Self> {
        let id: i64 = store
            .query_row("SELECT id FROM identity ORDER BY id LIMIT 1", [], |r| {
                r.get(0)
            })?
            .ok_or(Error::Unavailable)?;
        let identity = store.identity_secret(id)?.ok_or(Error::Unavailable)?;
        if identity.len() != IDENTITY_LEN || identity.first() != Some(&VER) {
            return Err(Error::Unavailable);
        }
        let stored = store.contacts()?;
        let contacts = stored
            .iter()
            .map(|c| {
                Ok(BackupContact {
                    iks: c.iks.clone(),
                    verified: c.verified,
                    profile: c.profile.clone().ok_or(Error::Unavailable)?,
                    local_name: c.display_name.clone().unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let settings = read_settings(store)?;
        let messages = read_messages(store, &stored)?;
        Ok(Self {
            identity,
            contacts,
            settings,
            messages,
        })
    }

    /// The four sections, encoded (ADR-053 Appendix).
    fn encode(&self) -> Result<[Zeroizing<Vec<u8>>; 4]> {
        let mut contacts = Zeroizing::new(len_u32(self.contacts.len())?.to_be_bytes().to_vec());
        for c in &self.contacts {
            if c.iks.len() != secmp_proto::sizes::IKS_PUBLIC_LEN
                || c.local_name.len() > LOCAL_NAME_MAX
            {
                return Err(Error::Unavailable);
            }
            contacts.extend_from_slice(&c.iks);
            contacts.push(u8::from(c.verified));
            contacts.extend_from_slice(&c.profile);
            contacts.push(u8::try_from(c.local_name.len()).map_err(|_| Error::Unavailable)?);
            contacts.extend_from_slice(c.local_name.as_bytes());
        }
        let n = u16::try_from(self.settings.len()).map_err(|_| Error::Unavailable)?;
        let mut settings = Zeroizing::new(n.to_be_bytes().to_vec());
        for (key, val) in &self.settings {
            settings.push(u8::try_from(key.len()).map_err(|_| Error::Unavailable)?);
            settings.extend_from_slice(key.as_bytes());
            let len = u16::try_from(val.len()).map_err(|_| Error::Unavailable)?;
            settings.extend_from_slice(&len.to_be_bytes());
            settings.extend_from_slice(val);
        }
        let mut messages = Zeroizing::new(len_u32(self.messages.len())?.to_be_bytes().to_vec());
        for m in &self.messages {
            if m.kind == KIND_VIEW_ONCE {
                return Err(Error::Unsupported);
            }
            messages.extend_from_slice(&m.contact_index.to_be_bytes());
            messages.push(match m.direction {
                Direction::In => 0,
                Direction::Out => 1,
            });
            messages.extend_from_slice(&m.ts_ms.to_be_bytes());
            let kind = secmp_proto::wire::cell::AppKind::ALL
                .into_iter()
                .find(|k| k.byte() == m.kind)
                .ok_or(Error::Unavailable)?;
            let app = AppMessage {
                msg_id: m.msg_id,
                kind,
                expire_after: m.expire_after,
                payload: m.payload.clone(),
            };
            messages.extend_from_slice(&app.encode().map_err(|_| Error::Unavailable)?);
        }
        Ok([self.identity.clone(), contacts, settings, messages])
    }
}

/// The settings of `store` whose key is in [`BACKUP_SETTINGS_KEYS`], by key (A4-1-04). Each value is a u32 (EXT1-3,
/// Q177): an INTEGER in the store, 4 bytes big-endian in the backup; a value outside the u32 range is `Unavailable`.
fn read_settings(store: &Store) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let mut out = Vec::new();
    for key in BACKUP_SETTINGS_KEYS {
        let value = store.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, i64>(0),
        )?;
        if let Some(v) = value {
            let v = u32::try_from(v).map_err(|_| Error::Unavailable)?;
            out.push(((*key).to_owned(), Zeroizing::new(v.to_be_bytes().to_vec())));
        }
    }
    Ok(out)
}

/// A `messages` row as [`read_messages`] selects it.
type MessageRow = (i64, i64, i64, i64, Option<i64>, Vec<u8>, Zeroizing<Vec<u8>>);

/// The messages of `store` in history order, each with the index of its contact in `contacts` (a message of a contact
/// that is not in `contacts` has no index and is not exported); a view-once is never in the history (CS-3.4) and is
/// excluded here as well.
fn read_messages(
    store: &Store,
    contacts: &[crate::contacts::StoredContact],
) -> Result<Vec<BackupMessage>> {
    let mut stmt = store
        .conn
        .prepare(
            "SELECT contact_id, direction, kind, ts_ms, expire_at_ms, msg_id, payload FROM messages \
             WHERE kind != ?1 ORDER BY id",
        )
        .map_err(|_| Error::Unavailable)?;
    let rows = stmt
        .query_map(params![i64::from(KIND_VIEW_ONCE)], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                Zeroizing::new(r.get(6)?),
            ))
        })
        .map_err(|_| Error::Unavailable)?;
    let mut out = Vec::new();
    for row in rows {
        let (contact_id, direction, kind, ts, expire_at, msg_id, payload): MessageRow =
            row.map_err(|_| Error::Unavailable)?;
        let Some(index) = contacts.iter().position(|c| c.id == contact_id) else {
            continue;
        };
        let ts_ms = u64::try_from(ts).map_err(|_| Error::Unavailable)?;
        let expire_after = match expire_at {
            None => 0,
            Some(at) => {
                let ms = u64::try_from(at.checked_sub(ts).ok_or(Error::Unavailable)?)
                    .map_err(|_| Error::Unavailable)?;
                u32::try_from(ms.checked_div(1000).unwrap_or(0)).map_err(|_| Error::Unavailable)?
            }
        };
        out.push(BackupMessage {
            contact_index: len_u32(index)?,
            direction: if direction == 0 {
                Direction::In
            } else {
                Direction::Out
            },
            ts_ms,
            msg_id: <[u8; 16]>::try_from(msg_id.as_slice()).map_err(|_| Error::Unavailable)?,
            kind: u8::try_from(kind).map_err(|_| Error::Unavailable)?,
            expire_after,
            payload,
        });
    }
    Ok(out)
}

/// `"SecMP-STORE/1 bwrap" ‖ ver ‖ salt ‖ params` (ADR-053 item 6).
fn bwrap_ad(salt: &[u8; 16], params: &[u8; 12]) -> Vec<u8> {
    [Label::StoreBwrap.as_bytes(), &[VER], salt, params].concat()
}

/// `"SecMP-STORE/1 backup" ‖ header` (ADR-053 item 6).
fn body_ad(header: &[u8]) -> Vec<u8> {
    [Label::StoreBackup.as_bytes(), header].concat()
}

/// The file of `sections` under `passphrase` with `params` (ADR-053 item 6): fresh salt, `MK_bk`, `N'`, `N`, in this
/// order. `table` is the section table's entries (the four tags with the sections' lengths, as [`export_bytes`] gives
/// them; a test may give others).
fn seal_file(
    passphrase: &[u8],
    params: Argon2Params,
    table: &[(u8, u32)],
    body: &[u8],
) -> Result<Vec<u8>> {
    let salt = crate::rand::public::<16>()?;
    let mk_bk = crate::rand::key()?;
    let enc = params.encode();
    let kek_bk = kek(passphrase, &salt, params).map_err(|_| Error::Unavailable)?;
    let nonce_w = crate::rand::nonce()?;
    let n_w = *nonce_w.as_bytes();
    // spec §3.4; ADR-053 item 6
    let wrapped = Caead::seal_locked(
        kek_bk.locked(),
        nonce_w,
        &bwrap_ad(&salt, &enc),
        mk_bk.locked().expose_secret(),
    )
    .map_err(|_| Error::Unavailable)?;
    let mut header = [&[VER][..], &salt, &enc, &n_w, &wrapped].concat();
    header.push(u8::try_from(table.len()).map_err(|_| Error::Unavailable)?);
    for (tag, len) in table {
        header.push(*tag);
        header.extend_from_slice(&len.to_be_bytes());
    }
    // spec §3.4; ADR-053 item 6
    let k_bk = derive(mk_bk.locked(), Label::StoreBackup)?;
    let nonce = crate::rand::nonce()?;
    let n = *nonce.as_bytes();
    // spec §3.4; ADR-053 item 6
    let sealed = Caead::seal_locked(k_bk.locked(), nonce, &body_ad(&header), body)
        .map_err(|_| Error::Unavailable)?;
    Ok([&MAGIC[..], &header, &n, &sealed].concat())
}

/// The backup file of `store` under `passphrase` with `params`.
fn export_bytes(store: &Store, passphrase: &[u8], params: Argon2Params) -> Result<Vec<u8>> {
    let sections = Contents::of(store)?.encode()?;
    let mut table = Vec::with_capacity(4);
    for (tag, s) in TAGS.iter().zip(&sections) {
        table.push((*tag, len_u32(s.len())?));
    }
    let mut body = Zeroizing::new(Vec::new());
    for s in &sections {
        body.extend_from_slice(s);
    }
    seal_file(passphrase, params, &table, &body)
}

/// Write the backup file of `store` to `path` with `params` (feature `kat`: the small parameters of the test rows; the
/// export confirmation and the cloud-folder refusal are [`export`]'s).
///
/// # Errors
/// [`Error::Unavailable`] if the profile has no identity, a value does not fit its field, or the file cannot be
/// written.
#[cfg(any(test, feature = "kat"))]
pub fn export_kat(
    store: &Store,
    path: &Path,
    passphrase: &[u8],
    params: Argon2Params,
) -> Result<()> {
    export_checked(store, path, passphrase, (true, true), params)
}

/// The fields of a backup file that the byte checks accepted.
struct Parts<'a> {
    salt: [u8; 16],
    enc: [u8; 12],
    n_w: [u8; 24],
    wrapped: &'a [u8],
    header: &'a [u8],
    n: [u8; 24],
    sealed: &'a [u8],
    lens: [usize; 4],
}

fn array<const N: usize>(b: &[u8]) -> Result<[u8; N]> {
    b.try_into().map_err(|_| Error::Unlock)
}

/// The checks decided from the file bytes alone, before the KDF: magic, `ver`, `params` = `accept`, the section table
/// (four entries, tags 1–4 in order) and the total length.
fn parse(file: &[u8], accept: Argon2Params) -> Result<Parts<'_>> {
    let (magic, rest) = file.split_at_checked(MAGIC.len()).ok_or(Error::Unlock)?;
    let (header, rest) = rest.split_at_checked(HEADER_LEN).ok_or(Error::Unlock)?;
    let (n, sealed) = rest.split_at_checked(24).ok_or(Error::Unlock)?;
    if magic != MAGIC {
        return Err(Error::Unlock);
    }
    let (ver, h) = header.split_at_checked(1).ok_or(Error::Unlock)?;
    let (salt, h) = h.split_at_checked(16).ok_or(Error::Unlock)?;
    let (enc, h) = h.split_at_checked(12).ok_or(Error::Unlock)?;
    let (bwrap, table) = h.split_at_checked(BWRAP_LEN).ok_or(Error::Unlock)?;
    let (n_w, wrapped) = bwrap.split_at_checked(24).ok_or(Error::Unlock)?;
    if ver != [VER] || enc != accept.encode() {
        return Err(Error::Unlock);
    }
    let (count, entries) = table.split_first().ok_or(Error::Unlock)?;
    if usize::from(*count) != TAGS.len() {
        return Err(Error::Unlock);
    }
    let mut lens = [0_usize; 4];
    let mut body_len = 0_usize;
    for ((entry, want), len) in entries.chunks(5).zip(TAGS).zip(&mut lens) {
        let (tag, l) = entry.split_first().ok_or(Error::Unlock)?;
        if *tag != want {
            return Err(Error::Unlock);
        }
        *len = usize::try_from(u32::from_be_bytes(array(l)?)).map_err(|_| Error::Unlock)?;
        body_len = body_len.checked_add(*len).ok_or(Error::Unlock)?;
    }
    if Some(file.len()) != body_len.checked_add(FILE_OVERHEAD) {
        return Err(Error::Unlock);
    }
    Ok(Parts {
        salt: array(salt)?,
        enc: array(enc)?,
        n_w: array(n_w)?,
        wrapped,
        header,
        n: array(n)?,
        sealed,
        lens,
    })
}

/// A cursor over one section.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(Error::Unlock)?;
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        let (b, rest) = self.0.split_first().ok_or(Error::Unlock)?;
        self.0 = rest;
        Ok(*b)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(array(self.take(2)?)?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(array(self.take(4)?)?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(array(self.take(8)?)?))
    }
    fn len(&mut self) -> Result<usize> {
        usize::try_from(self.u32()?).map_err(|_| Error::Unlock)
    }
    fn finish(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Unlock)
        }
    }
}

/// The length of the D.3 `Profile` at the front of `rest` (`name_len u8 ‖ name ‖ has_avatar u8 ‖ [sha256]`).
fn profile_len(rest: &[u8]) -> Result<usize> {
    let name = usize::from(*rest.first().ok_or(Error::Unlock)?);
    let flag_at = name.checked_add(1).ok_or(Error::Unlock)?;
    // the flag byte, and the avatar hash after a flag of 1
    let tail = match rest.get(flag_at) {
        Some(0) => 1,
        Some(1) => 33,
        _ => return Err(Error::Unlock),
    };
    flag_at.checked_add(tail).ok_or(Error::Unlock)
}

/// The four sections of a decrypted body (`lens` from the section table), each consuming exactly its length; every
/// field is checked (`IKSPublic` and `Profile` by the `secmp-proto` decoders, `AppMessage` likewise and never view-once).
fn decode(body: &[u8], lens: [usize; 4]) -> Result<Contents> {
    let mut sections: [&[u8]; 4] = [&[]; 4];
    let mut rest = body;
    for (s, len) in sections.iter_mut().zip(lens) {
        let (head, tail) = rest.split_at_checked(len).ok_or(Error::Unlock)?;
        *s = head;
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Error::Unlock);
    }
    let [identity, contacts_s, settings_s, messages_s] = sections;
    if identity.len() != IDENTITY_LEN || identity.first() != Some(&VER) {
        return Err(Error::Unlock);
    }
    let mut c = Cursor(contacts_s);
    let n = c.len()?;
    let mut contacts = Vec::new();
    for _ in 0..n {
        let iks = c.take(secmp_proto::sizes::IKS_PUBLIC_LEN)?;
        IksPublic::decode(iks).map_err(|_| Error::Unlock)?;
        let verified = match c.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Unlock),
        };
        let profile = c.take(profile_len(c.0)?)?;
        Profile::decode(profile).map_err(|_| Error::Unlock)?;
        let name_len = usize::from(c.u8()?);
        if name_len > LOCAL_NAME_MAX {
            return Err(Error::Unlock);
        }
        let name = core::str::from_utf8(c.take(name_len)?).map_err(|_| Error::Unlock)?;
        contacts.push(BackupContact {
            iks: iks.to_vec(),
            verified,
            profile: profile.to_vec(),
            local_name: name.to_owned(),
        });
    }
    c.finish()?;
    let mut s = Cursor(settings_s);
    let n = s.u16()?;
    let mut settings = Vec::new();
    for _ in 0..n {
        let key_len = usize::from(s.u8()?);
        let key = s.take(key_len)?;
        if !key.is_ascii() {
            return Err(Error::Unlock);
        }
        let key = core::str::from_utf8(key)
            .map_err(|_| Error::Unlock)?
            .to_owned();
        // only allowlisted keys, each value a u32 (ADR-053 Amendment 2)
        let val_len = usize::from(s.u16()?);
        if !BACKUP_SETTINGS_KEYS.contains(&key.as_str()) || val_len != 4 {
            return Err(Error::Unlock);
        }
        settings.push((key, Zeroizing::new(s.take(val_len)?.to_vec())));
    }
    s.finish()?;
    let mut m = Cursor(messages_s);
    let n = m.len()?;
    let mut messages = Vec::new();
    for _ in 0..n {
        let contact_index = m.u32()?;
        if usize::try_from(contact_index).map_err(|_| Error::Unlock)? >= contacts.len() {
            return Err(Error::Unlock);
        }
        let direction = match m.u8()? {
            0 => Direction::In,
            1 => Direction::Out,
            _ => return Err(Error::Unlock),
        };
        let ts_ms = m.u64()?;
        // AppMessage = msg_id[16] ‖ kind u8 ‖ expire_after u32 ‖ payload_len u16 ‖ payload (D.5)
        let len_at = m.0.get(21..23).ok_or(Error::Unlock)?;
        let payload_len = usize::from(u16::from_be_bytes(array(len_at)?));
        let app =
            AppMessage::decode(m.take(23_usize.checked_add(payload_len).ok_or(Error::Unlock)?)?)
                .map_err(|_| Error::Unlock)?;
        let kind = app.kind.byte();
        if kind == KIND_VIEW_ONCE {
            return Err(Error::Unlock);
        }
        messages.push(BackupMessage {
            contact_index,
            direction,
            ts_ms,
            msg_id: app.msg_id,
            kind,
            expire_after: app.expire_after,
            payload: app.payload,
        });
    }
    m.finish()?;
    Ok(Contents {
        identity: Zeroizing::new(identity.to_vec()),
        contacts,
        settings,
        messages,
    })
}

/// The decrypted body of `file` under `passphrase`, accepting `accept`, with the section lengths.
fn open_body(
    file: &[u8],
    passphrase: &[u8],
    accept: Argon2Params,
) -> Result<(Zeroizing<Vec<u8>>, [usize; 4])> {
    let p = parse(file, accept)?;
    let kek_bk = kek(passphrase, &p.salt, accept)?;
    // spec §3.4; ADR-053 item 6
    let mk = Caead::open_locked(
        kek_bk.locked(),
        &p.n_w,
        &bwrap_ad(&p.salt, &p.enc),
        p.wrapped,
    )
    .map_err(|_| Error::Unlock)?;
    let mk = LockedSecret::<32>::from_slice(&mk).map_err(kdf_error)?;
    // spec §3.4; ADR-053 item 6
    let k_bk = derive(&mk, Label::StoreBackup).map_err(|_| Error::Unlock)?;
    // spec §3.4; ADR-053 item 6
    let body = Caead::open_locked(k_bk.locked(), &p.n, &body_ad(p.header), p.sealed)
        .map_err(|_| Error::Unlock)?;
    Ok((body, p.lens))
}

/// The contents of `file` under `passphrase`, accepting `accept`.
fn open_export(file: &[u8], passphrase: &[u8], accept: Argon2Params) -> Result<Contents> {
    let (body, lens) = open_body(file, passphrase, accept)?;
    decode(&body, lens)
}

/// The contents of the backup file bytes `file` under `passphrase` with the `kat` Argon2 parameters (feature `kat`:
/// the fuzz target `backup_import`, the test rows; no file access).
///
/// # Errors
/// [`Error::Unlock`] — uniformly — for any file that is not a well-formed backup under `passphrase`.
#[cfg(feature = "kat")]
pub fn open_export_kat(file: &[u8], passphrase: &[u8]) -> Result<Contents> {
    open_export(file, passphrase, Argon2Params::kat_small())
}

/// The file of `body` with the section table `table` under `passphrase` and the `kat` Argon2 parameters (feature `kat`:
/// the fuzz target `backup_import` seals structured bodies, whose table it chooses, to reach the section decoders).
///
/// # Errors
/// [`Error::Unavailable`] if randomness is unavailable or the table has more than 255 entries.
#[cfg(feature = "kat")]
pub fn seal_file_kat(passphrase: &[u8], table: &[(u8, u32)], body: &[u8]) -> Result<Vec<u8>> {
    seal_file(passphrase, Argon2Params::kat_small(), table, body)
}

/// The body that [`Contents`] encodes to (feature `kat`: the fuzz target `backup_import` checks that an accepted body
/// is canonical).
///
/// # Errors
/// [`Error::Unavailable`] if a value does not fit its field.
#[cfg(feature = "kat")]
pub fn encode_body_kat(contents: &Contents) -> Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    for s in &contents.encode()? {
        body.extend_from_slice(s);
    }
    Ok(body)
}

/// The decrypted body of `file` (feature `kat`: BK-02 and the view-once row search it).
///
/// # Errors
/// As [`open_export_kat`].
#[cfg(feature = "kat")]
pub fn open_body_kat(file: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    open_body(file, passphrase, Argon2Params::kat_small()).map(|(b, _)| b)
}

/// Restore the backup file at `path` into the empty profile `store` (CS-3.5): the identity, every contact with state
/// [`STATE_REINVITE_REQUIRED`] (Q142), the settings and the messages, in one transaction, created at `now_ms`. No
/// session, prekey, outbox, relay or invitation row is written: the client generates fresh prekeys, and every contact
/// must be re-invited.
///
/// # Errors
/// [`Error::Unlock`] — uniformly — for a file that is not a well-formed backup under `passphrase`;
/// [`Error::Unavailable`] if the file cannot be read, `store` is not empty, or the write fails. Nothing is written on
/// any error.
pub fn import(store: &mut Store, path: &Path, passphrase: &[u8], now_ms: u64) -> Result<()> {
    let file = std::fs::read(path).map_err(|_| Error::Unavailable)?;
    import_bytes(store, &file, passphrase, Argon2Params::PROFILE, now_ms)
}

/// [`import`] accepting `accept` (feature `kat`).
///
/// # Errors
/// As [`import`].
#[cfg(any(test, feature = "kat"))]
pub fn import_kat(
    store: &mut Store,
    path: &Path,
    passphrase: &[u8],
    accept: Argon2Params,
    now_ms: u64,
) -> Result<()> {
    let file = std::fs::read(path).map_err(|_| Error::Unavailable)?;
    import_bytes(store, &file, passphrase, accept, now_ms)
}

/// The fingerprint of the identity section (its public keys from the seed forms; §6.2).
fn identity_fingerprint(identity: &[u8]) -> Result<[u8; 32]> {
    let (ed, rest) = identity
        .get(1..)
        .ok_or(Error::Unlock)?
        .split_at_checked(32)
        .ok_or(Error::Unlock)?;
    let (mldsa, x) = rest.split_at_checked(32).ok_or(Error::Unlock)?;
    let sig = HybridSigningKey::from_seeds(ed, mldsa).map_err(|_| Error::Unlock)?;
    let dh = IkDhSecret::from_bytes(x).map_err(|_| Error::Unlock)?;
    IdentityKeys::from_parts(sig, dh)
        .and_then(|k| k.fingerprint())
        .map_err(|_| Error::Unlock)
}

fn import_bytes(
    store: &mut Store,
    file: &[u8],
    passphrase: &[u8],
    accept: Argon2Params,
    now_ms: u64,
) -> Result<()> {
    let contents = open_export(file, passphrase, accept)?;
    let own_fp = identity_fingerprint(&contents.identity)?;
    let mut peer_fps = Vec::with_capacity(contents.contacts.len());
    for c in &contents.contacts {
        let iks = IksPublic::decode(&c.iks).map_err(|_| Error::Unlock)?;
        peer_fps.push(fingerprint_of(&iks).map_err(|_| Error::Unlock)?);
    }
    let empty: i64 = store
        .query_row(
            "SELECT (SELECT count(*) FROM identity) + (SELECT count(*) FROM contacts) + (SELECT count(*) FROM messages) \
             + (SELECT count(*) FROM prekeys) + (SELECT count(*) FROM invitations) + (SELECT count(*) FROM sessions) \
             + (SELECT count(*) FROM relays) + (SELECT count(*) FROM outbox) \
             + (SELECT count(*) FROM settings)",
            [],
            |r| r.get(0),
        )?
        .unwrap_or(1);
    if empty != 0 {
        return Err(Error::Unavailable);
    }
    store.txn(|tx| {
        put_identity(tx, 1, &contents.identity, &own_fp, now_ms)?;
        let mut ids = Vec::with_capacity(contents.contacts.len());
        for ((c, fp), id) in contents.contacts.iter().zip(&peer_fps).zip(1_i64..) {
            put_contact(
                tx,
                &Contact {
                    id,
                    iks: &c.iks,
                    fingerprint: fp,
                    display_name: (!c.local_name.is_empty()).then_some(c.local_name.as_str()),
                    verified: c.verified,
                    routes: None,
                    queues: None,
                    state: STATE_REINVITE_REQUIRED,
                    profile: Some(&c.profile),
                },
            )?;
            ids.push(id);
        }
        for (key, val) in &contents.settings {
            let v = <[u8; 4]>::try_from(val.as_slice()).map_err(|_| Error::Unavailable)?;
            tx.exec(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, i64::from(u32::from_be_bytes(v))],
            )?;
        }
        for m in &contents.messages {
            let index = usize::try_from(m.contact_index).map_err(|_| Error::Unavailable)?;
            let contact_id = *ids.get(index).ok_or(Error::Unavailable)?;
            let ts = i64::try_from(m.ts_ms).map_err(|_| Error::Unavailable)?;
            let expire_at = crate::messages::expire_at(m.ts_ms, m.expire_after)?;
            let direction: i64 = match m.direction {
                Direction::In => 0,
                Direction::Out => 1,
            };
            tx.exec(
                "INSERT OR IGNORE INTO messages (contact_id, msg_id, direction, kind, ts_ms, expire_at_ms, payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![contact_id, m.msg_id.as_slice(), direction, i64::from(m.kind), ts, expire_at, m.payload.as_slice()],
            )?;
        }
        Ok(())
    })
}

#[cfg(feature = "kat")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{TempDir, TestKey, contains, fixed_random};
    use crate::messages::NewMessage;
    use crate::outbox::{OutboxRow, state};
    use crate::profile::{insert_invitation, insert_prekey, put_relay};
    use crate::sessions::{insert_skipped, put_fixed, put_inbox, put_trust};

    type R = core::result::Result<(), Box<dyn std::error::Error>>;
    type Res<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    const PASS: &[u8] = b"backup passphrase";

    /// The identity section of the source profile.
    fn identity() -> Vec<u8> {
        [&[VER][..], &[0x11; 32], &[0x22; 32], &[0x33; 32]].concat()
    }

    /// The `IKSPublic` of peer `n` (from fixed seeds).
    fn peer_iks(n: u8) -> Res<Vec<u8>> {
        let sig = HybridSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(1); 32])?;
        let dh = IkDhSecret::from_bytes(&[n.wrapping_add(2); 32])?;
        Ok(IdentityKeys::from_parts(sig, dh)?
            .public()
            .encode()?
            .to_vec())
    }

    /// The secrets a populated profile holds outside the four backup sections (CS-3.5): session parts, skipped
    /// entries, prekey seeds, the outbox payload and cell, the relay access key and the invitation record.
    fn secrets() -> Vec<Vec<u8>> {
        let distinct = |tag: u8, n: usize| -> Vec<u8> {
            (0..n)
                .map(|i| tag ^ u8::try_from(i % 251).unwrap_or(0).wrapping_mul(7))
                .collect()
        };
        vec![
            distinct(0xa1, 600), // session 1 fixed part (RatchetStateV1: rk, ck, hk, …)
            distinct(0xa2, 68),  // session 1 skipped entry (hk ‖ n ‖ mk)
            distinct(0xa3, 120), // session 1 reassembly state
            distinct(0xa4, 600), // session 2 fixed part
            distinct(0xa5, 68),  // session 2 skipped entry
            distinct(0xb1, 96),  // SPK secret seeds
            distinct(0xb2, 64),  // OPK secret seed
            distinct(0xb3, 64),  // RPK secret seed
            distinct(0xc1, 300), // an unsent outbox payload
            distinct(0xd1, 32),  // the relay access key (queue seed)
            distinct(0xe1, 150), // the invitation record (link_key)
        ]
    }

    /// A populated source profile: the identity, two contacts, two settings, a received and a sent message — and the
    /// [`secrets`] in sessions, prekeys, the outbox, a relay and an invitation.
    fn populate(store: &mut Store) -> R {
        let s = secrets();
        let get = |i: usize| s.get(i).cloned().unwrap_or_default();
        let (bob, carol) = (peer_iks(1)?, peer_iks(9)?);
        let profile = Profile::new("Bob", None)?.encode()?;
        let profile_c = Profile::new("Carol", Some([4; 32]))?.encode()?;
        store.txn(|tx| {
            put_identity(tx, 1, &identity(), b"own fingerprint", 5)?;
            for (id, iks, p, name, verified) in [
                (1, &bob, &profile, Some("Bobby"), true),
                (2, &carol, &profile_c, None, false),
            ] {
                put_contact(
                    tx,
                    &Contact {
                        id,
                        iks,
                        fingerprint: b"peer fingerprint",
                        display_name: name,
                        verified,
                        routes: Some(b"routes"),
                        queues: Some(b"queues"),
                        state: crate::contacts::STATE_ACTIVE,
                        profile: Some(p),
                    },
                )?;
            }
            put_fixed(tx, 1, &get(0))?;
            insert_skipped(tx, 1, 0, &get(1))?;
            put_inbox(tx, 1, &get(2))?;
            put_trust(tx, 1, &[1])?;
            put_fixed(tx, 2, &get(3))?;
            insert_skipped(tx, 2, 0, &get(4))?;
            insert_prekey(tx, 1, 1, &get(5), Some(9))?;
            insert_prekey(tx, 2, 7, &get(6), None)?;
            insert_prekey(tx, 3, 1, &get(7), None)?;
            put_relay(tx, 1, b"relay ref", Some(&get(9)))?;
            insert_invitation(tx, &[5; 16], &get(10), 9)
        })?;
        store.outbox_insert(
            1,
            &OutboxRow {
                msg_id: [6; 16],
                seq: 0,
                kind: 1,
                expire_after: 0,
                payload: Zeroizing::new(get(8)),
                queued_ms: 1,
                first_relayed_ms: None,
                state: state::QUEUED,
                cell_id: None,
            },
        )?;
        store.connection_kat().execute(
            "INSERT INTO settings (key, value) VALUES ('retention_days', ?1), ('theme', x'01')",
            rusqlite::params![30_i64],
        )?;
        for (msg_id, direction, ts_ms, expire_after, payload) in [
            (
                [1; 16],
                Direction::In,
                1_000,
                0,
                b"hello from bob".as_slice(),
            ),
            ([2; 16], Direction::Out, 2_000, 60, b"hello bob".as_slice()),
        ] {
            store.insert_message(&NewMessage {
                contact_id: 1,
                msg_id,
                direction,
                kind: 1,
                ts_ms,
                expire_after,
                payload,
            })?;
        }
        Ok(())
    }

    /// A populated profile in `dir` and its export (`kat_small`), the file bytes.
    fn exported(label: &str) -> Res<(TempDir, Vec<u8>)> {
        let dir = TempDir::new(label)?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        let path = dir.path().join("export.secmpbackup");
        export_kat(&store, &path, PASS, Argon2Params::kat_small())?;
        let file = std::fs::read(&path)?;
        Ok((dir, file))
    }

    /// The section table of `file`: (tag, len) × count.
    fn table(file: &[u8]) -> Vec<(u8, u32)> {
        let at = 13 + 1 + 16 + 12 + BWRAP_LEN;
        let entries = file.get(at + 1..at + SECTION_TABLE_LEN).unwrap_or_default();
        entries
            .chunks(5)
            .filter_map(|e| {
                let (tag, len) = e.split_first()?;
                Some((*tag, u32::from_be_bytes(len.try_into().ok()?)))
            })
            .collect()
    }

    /// BK-01 (CS-3.5; ADR-053 item 6, Appendix): the export of a populated profile holds exactly the four sections —
    /// identity (the IKS seed forms), contacts (peer `IKSPublic`, verified flag, the user's name, `Profile`), settings,
    /// messages — and decrypts under the backup passphrase to the profile's values.
    #[test]
    fn contents_whitelist() -> R {
        let (_dir, file) = exported("bk01")?;
        assert_eq!(file.get(..13), Some(MAGIC.as_slice()));
        assert_eq!(
            file.get(13 + 1 + 16 + 12 + BWRAP_LEN),
            Some(&4),
            "count = 4"
        );
        let t = table(&file);
        assert_eq!(t.iter().map(|(tag, _)| *tag).collect::<Vec<_>>(), TAGS);
        let body_len: usize = t
            .iter()
            .map(|(_, l)| usize::try_from(*l).unwrap_or(usize::MAX))
            .sum();
        assert_eq!(file.len(), FILE_OVERHEAD + body_len);
        let c = open_export_kat(&file, PASS)?;
        assert_eq!(c.identity.as_slice(), identity().as_slice());
        assert_eq!(
            t.first().map(|(_, l)| *l),
            Some(97),
            "identity section 97 B (Q143)"
        );
        let contacts: Vec<(Vec<u8>, bool, &str, Vec<u8>)> = c
            .contacts
            .iter()
            .map(|k| {
                (
                    k.iks.clone(),
                    k.verified,
                    k.local_name.as_str(),
                    k.profile.clone(),
                )
            })
            .collect();
        assert_eq!(
            contacts,
            vec![
                (
                    peer_iks(1)?,
                    true,
                    "Bobby",
                    Profile::new("Bob", None)?.encode()?.to_vec()
                ),
                (
                    peer_iks(9)?,
                    false,
                    "",
                    Profile::new("Carol", Some([4; 32]))?.encode()?.to_vec()
                ),
            ]
        );
        let settings: Vec<(&str, &[u8])> = c
            .settings
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect();
        assert_eq!(
            settings,
            vec![("retention_days", [0, 0, 0, 0x1e].as_slice())]
        );
        let messages: Vec<String> = c
            .messages
            .iter()
            .map(|m| {
                let head = (m.contact_index, m.direction, m.ts_ms, m.msg_id);
                format!(
                    "{head:?} {} {} {:?}",
                    m.kind,
                    m.expire_after,
                    m.payload.as_slice()
                )
            })
            .collect();
        let want = |head: (u32, Direction, u64, [u8; 16]), expire: u32, payload: &[u8]| {
            format!("{head:?} 1 {expire} {payload:?}")
        };
        assert_eq!(
            messages,
            [
                want((0, Direction::In, 1_000, [1; 16]), 0, b"hello from bob"),
                want((0, Direction::Out, 2_000, [2; 16]), 60, b"hello bob"),
            ]
        );
        Ok(())
    }

    /// BK-02 (CS-3.5; spec §7.2 "a restored backup MUST NOT contain ratchet state"): no 16-byte window of any session
    /// part, skipped entry, prekey seed, outbox payload, relay access key or invitation record occurs in the decrypted
    /// export.
    #[test]
    fn no_ratchet_material() -> R {
        let (_dir, file) = exported("bk02")?;
        let body = open_body_kat(&file, PASS)?;
        for (i, s) in secrets().iter().enumerate() {
            for (at, w) in s.windows(16).enumerate() {
                assert!(!contains(&body, w), "secret {i} at {at}");
            }
        }
        Ok(())
    }

    /// BK-03, store half (CS-3.5; Q142): imported into a fresh profile, every contact is `STATE_REINVITE_REQUIRED`,
    /// there is no session, prekey, outbox, relay or invitation row (fresh prekeys are the client's, Phase B), and the
    /// identity, the settings and the messages are the source's. (`Api.send` → `ReinviteRequired` and the prekey
    /// generation are Phase B.)
    #[test]
    fn restore_requires_reinvite() -> R {
        let (dir, file) = exported("bk03")?;
        let path = dir.path().join("export.secmpbackup");
        assert_eq!(std::fs::read(&path)?, file);
        let mut fresh = Store::open(&dir.path().join("restored"), &TestKey::db_key())?;
        import_kat(&mut fresh, &path, PASS, Argon2Params::kat_small(), 77)?;
        let contacts = fresh.contacts()?;
        assert_eq!(contacts.len(), 2);
        assert!(contacts.iter().all(|c| c.state == STATE_REINVITE_REQUIRED));
        assert_eq!(contacts.first().map(|c| c.iks.clone()), Some(peer_iks(1)?));
        for table in ["sessions", "prekeys", "outbox", "relays", "invitations"] {
            let n: i64 = fresh.connection_kat().query_row(
                &format!("SELECT count(*) FROM {table}"),
                [],
                |r| r.get(0),
            )?;
            assert_eq!(n, 0, "{table}");
        }
        assert_eq!(
            fresh.identity_secret(1)?.map(|z| z.to_vec()),
            Some(identity())
        );
        assert!(fresh.has_message(1, &[1; 16])? && fresh.has_message(1, &[2; 16])?);
        assert_eq!(
            import_kat(&mut fresh, &path, PASS, Argon2Params::kat_small(), 78),
            Err(Error::Unavailable),
            "not into a profile that is not empty"
        );
        Ok(())
    }

    /// BK-04 [REF] (ADR-053 item 6, Appendix): with fixed salt, `MK_bk`, `N'` and `N` (kat entropy, `kat_small`) the
    /// file has the magic, header, `bwrap`, section table and body seal at their offsets and lengths, and `bwrap` and
    /// the body seal equal the item-6 compositions recomputed from the `secmp-crypto` primitives; a wrong passphrase is
    /// `Err(Unlock)`. The byte-exact clause against `vectors/store.json` is open [REF] (OPEN-M7-38), as ST-10.
    #[test]
    fn wrapping_and_header_kat() -> R {
        let dir = TempDir::new("bk04")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        let (salt, mk_bk, n_w, n) = ([0x5a_u8; 16], [0x6b_u8; 32], [0x7c_u8; 24], [0x8d_u8; 24]);
        fixed_random(&[&salt[..], &mk_bk, &n_w, &n].concat());
        let path = dir.path().join("export");
        export_kat(&store, &path, PASS, Argon2Params::kat_small())?;
        let file = std::fs::read(&path)?;
        let params = Argon2Params::kat_small().encode();
        let at = |a: usize, b: usize| file.get(a..b).unwrap_or_default();
        assert_eq!(at(0, 13), MAGIC.as_slice());
        assert_eq!(at(13, 14), [VER].as_slice());
        assert_eq!(at(14, 30), salt.as_slice());
        assert_eq!(at(30, 42), params.as_slice());
        assert_eq!(at(42, 66), n_w.as_slice());
        assert_eq!(at(167, 191), n.as_slice());
        // bwrap = N' ‖ CAEAD.Seal(KEK_bk, N', "SecMP-STORE/1 bwrap" ‖ ver ‖ salt ‖ params, MK_bk)
        let kek_bk = secmp_crypto::argon2id::<32>(PASS, &salt, 64, 1, 1)?;
        let ad_w = [Label::StoreBwrap.as_bytes(), &[VER], &salt, &params].concat();
        let wrapped = Caead::seal(
            &kek_bk,
            secmp_crypto::Nonce24::from_bytes_kat(n_w),
            &ad_w,
            &mk_bk,
        )?;
        assert_eq!(at(66, 146), wrapped.as_slice());
        assert_eq!(42 + BWRAP_LEN, 146);
        let header = at(13, 13 + HEADER_LEN);
        assert_eq!(header.len(), 154);
        // body = N ‖ CAEAD.Seal(K_bk, N, "SecMP-STORE/1 backup" ‖ header, body), K_bk = HKDF(0^32, MK_bk, "SecMP-STORE/1 backup")
        let k_bk = secmp_crypto::hkdf::<32>(&[0; 32], &mk_bk, Label::StoreBackup, &[])?;
        let body = open_body_kat(&file, PASS)?;
        let ad = [Label::StoreBackup.as_bytes(), header].concat();
        let sealed = Caead::seal(&k_bk, secmp_crypto::Nonce24::from_bytes_kat(n), &ad, &body)?;
        assert_eq!(at(191, file.len()), sealed.as_slice());
        assert_eq!(
            open_export_kat(&file, b"backup passphrasf").err(),
            Some(Error::Unlock)
        );
        Ok(())
    }

    /// The row counts of every table import writes to.
    fn written(store: &Store) -> Res<i64> {
        Ok(store.connection_kat().query_row(
            "SELECT (SELECT count(*) FROM identity) + (SELECT count(*) FROM contacts) + \
             (SELECT count(*) FROM settings) + (SELECT count(*) FROM messages)",
            [],
            |r| r.get(0),
        )?)
    }

    /// BK-05 (CS-3.5; CLAUDE.md §4; Q125): a wrong version, a truncated file, a trailing byte, a section table naming
    /// a section twice (correctly sealed), a wrong magic, a wrong passphrase and a message of a contact the file does
    /// not hold (correctly sealed) are each the one uniform `Err(Unlock)` (equal values, equal `Debug`), and nothing is
    /// written.
    #[test]
    fn import_rejects_malformed() -> R {
        let (dir, file) = exported("bk05")?;
        let small = Argon2Params::kat_small();
        let flip = |at: usize| {
            let mut f = file.clone();
            if let Some(b) = f.get_mut(at) {
                *b ^= 1;
            }
            f
        };
        let body = open_body_kat(&file, PASS)?;
        let t = table(&file);
        let mut twice = t.clone();
        if let Some(e) = twice.get_mut(1) {
            e.0 = 1;
        }
        // a message section naming contact index 2 of two contacts
        let mut no_contact = body.to_vec();
        let msg_at = body.len() - usize::try_from(t.get(3).map_or(0, |e| e.1))?;
        if let Some(b) = no_contact.get_mut(msg_at + 4 + 3) {
            *b = 2;
        }
        let cases: Vec<(&str, Vec<u8>, &[u8])> = vec![
            ("wrong version", flip(13), PASS),
            (
                "truncated",
                file.get(..file.len() - 1).unwrap_or_default().to_vec(),
                PASS,
            ),
            ("trailing byte", [&file[..], &[0]].concat(), PASS),
            (
                "section twice",
                seal_file(PASS, small, &twice, &body)?,
                PASS,
            ),
            ("wrong magic", flip(0), PASS),
            ("wrong passphrase", file.clone(), b"another passphrase"),
            (
                "no such contact",
                seal_file(PASS, small, &t, &no_contact)?,
                PASS,
            ),
        ];
        assert!(
            open_export_kat(&seal_file(PASS, small, &t, &body)?, PASS).is_ok(),
            "the control re-seal opens"
        );
        let mut fresh = Store::open(&dir.path().join("restored"), &TestKey::db_key())?;
        for (name, bytes, pass) in &cases {
            let got = import_bytes(&mut fresh, bytes, pass, small, 1);
            assert_eq!(got, Err(Error::Unlock), "{name}");
            assert_eq!(
                format!("{got:?}"),
                format!("{:?}", Err::<(), _>(Error::Unlock)),
                "{name}"
            );
            assert_eq!(written(&fresh)?, 0, "{name}: nothing written");
        }
        Ok(())
    }

    /// Extra (BK-05; CS-3.4; Q125): a held received and a queued view-once with canaries are not exported — no kind-3
    /// record and no canary in the decrypted body.
    #[test]
    fn no_view_once_in_export() -> R {
        let dir = TempDir::new("bk-vo")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        let (held, queued) = (
            b"view-once canary held 0123456789",
            b"view-once canary queued 98765432",
        );
        store.hold_received_view_once([0x31; 16], held);
        store.queue_view_once([0x32; 16], queued)?;
        let path = dir.path().join("export");
        export_kat(&store, &path, PASS, Argon2Params::kat_small())?;
        let file = std::fs::read(&path)?;
        let body = open_body_kat(&file, PASS)?;
        assert!(!contains(&body, held) && !contains(&body, queued));
        assert!(!contains(&body, b"view-once canary"));
        let c = open_export_kat(&file, PASS)?;
        assert!(c.messages.iter().all(|m| m.kind != KIND_VIEW_ONCE));
        assert!(
            c.messages
                .iter()
                .all(|m| m.msg_id != [0x31; 16] && m.msg_id != [0x32; 16])
        );
        assert_eq!(c.messages.len(), 2);
        Ok(())
    }

    /// BK-06 [O-37] (CS-3.5; OPEN-M7-37 A, Q141): an export without `confirm` is `Err(ConfirmRequired)` with the
    /// warning text, before the cloud check; a path under `…/OneDrive/…` (any case) is `Err(CloudFolder)`; the same with
    /// `force` writes the file, which opens under the passphrase; nothing is written by a refused export.
    #[test]
    fn explicit_never_cloud() -> R {
        let dir = TempDir::new("bk06")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        let plain = dir.path().join("export");
        let refused = export(&store, &plain, PASS, false, false).err();
        assert_eq!(refused, Some(Error::ConfirmRequired));
        assert_eq!(
            refused.map(|e| e.to_string()).as_deref(),
            Some(
                "secmp-store: confirm the export: the file contains your identity keys, and after a restore every \
                 contact must be re-invited"
            )
        );
        let cloud = dir.path().join("OneDrive").join("Backups");
        std::fs::create_dir_all(&cloud)?;
        let file = cloud.join("export");
        assert_eq!(
            export(&store, &file, PASS, false, true),
            Err(Error::ConfirmRequired)
        );
        assert_eq!(
            export(&store, &file, PASS, true, false),
            Err(Error::CloudFolder)
        );
        assert!(!plain.exists() && !file.exists(), "nothing written");
        for f in CLOUD_FOLDERS {
            for name in [f.to_string(), f.to_lowercase(), f.to_uppercase()] {
                assert!(
                    in_cloud_folder(&Path::new("/home/u").join(&name).join("x")),
                    "{name}"
                );
            }
        }
        assert!(!in_cloud_folder(Path::new("/home/u/OneDriveX/Boxes/x")));
        export(&store, &file, PASS, true, true)?;
        let bytes = std::fs::read(&file)?;
        assert_eq!(
            bytes.get(30..42),
            Some(Argon2Params::PROFILE.encode().as_slice())
        );
        assert_eq!(
            open_export(&bytes, PASS, Argon2Params::PROFILE)?
                .contacts
                .len(),
            2
        );
        Ok(())
    }

    /// The product part (before the test module, CRLF-normalised) of every `crates/*/src/**/*.rs`, with its path.
    fn product_sources() -> Res<Vec<(String, String)>> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut out = Vec::new();
        let mut stack: Vec<std::path::PathBuf> = std::fs::read_dir(&crates)?
            .map(|e| e.map(|e| e.path().join("src")))
            .collect::<std::io::Result<_>>()?;
        while let Some(d) = stack.pop() {
            if !d.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&d)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path)?.replace("\r\n", "\n");
                    let product = text
                        .split("#[cfg(test)]\nmod tests")
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    out.push((path.to_string_lossy().into_owned(), product));
                }
            }
        }
        Ok(out)
    }

    /// A4-1-04: every settings key that product code names in a SQL literal is in exactly one of
    /// [`BACKUP_SETTINGS_KEYS`] and [`BACKUP_SETTINGS_EXCLUDED`]; a profile with `retention_days` and `theme` exports
    /// `retention_days` only.
    #[test]
    fn settings_allowlist_pinned() -> R {
        let mut found = Vec::new();
        for (path, product) in product_sources()? {
            for needle in [
                concat!("settings WHERE key = ", "'"),
                concat!("INTO settings (key, value) VALUES (", "'"),
            ] {
                for (at, _) in product.match_indices(needle) {
                    let rest = product
                        .get(at.saturating_add(needle.len())..)
                        .unwrap_or_default();
                    let key = rest.split('\'').next().unwrap_or_default().to_owned();
                    found.push((path.clone(), key));
                }
            }
        }
        assert!(!found.is_empty(), "the scan finds the retention key");
        for (path, key) in &found {
            let listed = BACKUP_SETTINGS_KEYS.contains(&key.as_str());
            let excluded = BACKUP_SETTINGS_EXCLUDED.contains(&key.as_str());
            assert!(
                listed != excluded,
                "settings key {key:?} ({path}) in neither or both lists"
            );
        }
        let dir = TempDir::new("bk-settings")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        store.connection_kat().execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('retention_days', ?1), ('theme', x'01')",
            rusqlite::params![30_i64],
        )?;
        let path = dir.path().join("export.secmpbackup");
        export_kat(&store, &path, PASS, Argon2Params::kat_small())?;
        let c = open_export_kat(&std::fs::read(&path)?, PASS)?;
        let keys: Vec<&str> = c.settings.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["retention_days"]);
        Ok(())
    }

    /// A backup of the populated profile whose settings section is replaced by `settings` (sealed again under `PASS`).
    fn forged(
        label: &str,
        settings: Vec<(&str, Vec<u8>)>,
    ) -> Res<(TempDir, std::path::PathBuf)> {
        let (dir, file) = exported(label)?;
        let mut contents = open_export_kat(&file, PASS)?;
        contents.settings = settings
            .into_iter()
            .map(|(k, v)| (k.to_owned(), Zeroizing::new(v)))
            .collect();
        let sections = contents.encode()?;
        let mut table = Vec::new();
        let mut body = Vec::new();
        for (tag, section) in (1_u8..).zip(&sections) {
            table.push((tag, len_u32(section.len())?));
            body.extend_from_slice(section);
        }
        let path = dir.path().join("forged.secmpbackup");
        std::fs::write(&path, seal_file_kat(PASS, &table, &body)?)?;
        Ok((dir, path))
    }

    /// The number of `settings` rows of `store`.
    fn settings_rows(store: &Store) -> Res<i64> {
        Ok(store
            .connection_kat()
            .query_row("SELECT count(*) FROM settings", [], |r| r.get(0))?)
    }

    /// EXT1-3 (Q177): `retention_days` is an INTEGER in the store and a u32 on the wire; a backup restores the
    /// retention that `Store::retention` reads.
    #[test]
    fn retention_round_trips_through_store_retention() -> R {
        use crate::messages::Retention;
        let dir = TempDir::new("bk-ret")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        store.connection_kat().execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('retention_days', ?1)",
            rusqlite::params![7_i64],
        )?;
        assert_eq!(store.retention(), Ok(Retention::Days(7)));
        let path = dir.path().join("export.secmpbackup");
        let small = Argon2Params::kat_small();
        assert_eq!(export_kat(&store, &path, PASS, small), Ok(()));
        let mut fresh = Store::open(&dir.path().join("fresh"), &TestKey::db_key())?;
        assert_eq!(import_kat(&mut fresh, &path, PASS, small, 1), Ok(()));
        assert_eq!(fresh.retention(), Ok(Retention::Days(7)));
        Ok(())
    }

    /// EXT1-3 (Q177): a `retention_days` value of another length than 4 is a malformed section (`Unlock`), nothing
    /// is written.
    #[test]
    fn retention_wire_length_other_than_4_rejected() -> R {
        for len in [3_usize, 8] {
            let (dir, path) = forged("bk-retlen", vec![("retention_days", vec![0; len])])?;
            let mut fresh = Store::open(&dir.path().join("fresh"), &TestKey::db_key())?;
            assert_eq!(
                import_kat(&mut fresh, &path, PASS, Argon2Params::kat_small(), 1),
                Err(Error::Unlock),
                "{len}"
            );
            assert_eq!(settings_rows(&fresh)?, 0, "{len}");
        }
        Ok(())
    }

    /// EXT1-4 (Q179a): a settings key outside [`BACKUP_SETTINGS_KEYS`] is a malformed section (`Unlock`), nothing is
    /// written.
    #[test]
    fn import_refuses_non_allowlisted_setting() -> R {
        let (dir, path) = forged("bk-allow", vec![("not_allowlisted", vec![1])])?;
        let mut fresh = Store::open(&dir.path().join("fresh"), &TestKey::db_key())?;
        assert_eq!(
            import_kat(&mut fresh, &path, PASS, Argon2Params::kat_small(), 1),
            Err(Error::Unlock)
        );
        assert_eq!(settings_rows(&fresh)?, 0);
        Ok(())
    }

    /// EXT1-4 (Q179b): a profile with a `settings` row is not empty (`Unavailable`), the row is unchanged.
    #[test]
    fn import_refuses_profile_with_settings() -> R {
        let (dir, file) = exported("bk-setrow")?;
        let path = dir.path().join("export.secmpbackup");
        assert!(path.exists());
        drop(file);
        let mut fresh = Store::open(&dir.path().join("fresh"), &TestKey::db_key())?;
        fresh
            .connection_kat()
            .execute("INSERT INTO settings (key, value) VALUES ('theme', x'01')", [])?;
        assert_eq!(
            import_kat(&mut fresh, &path, PASS, Argon2Params::kat_small(), 1),
            Err(Error::Unavailable)
        );
        assert_eq!(settings_rows(&fresh)?, 1);
        let theme: Vec<u8> = fresh.connection_kat().query_row(
            "SELECT value FROM settings WHERE key = 'theme'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(theme, [1]);
        Ok(())
    }

    /// A4-1-06 (EXT1-4, Q179b): an import is refused (`Unavailable`, nothing written) into a profile with a row in any of
    /// the nine tables `identity`, `contacts`, `messages`, `prekeys`, `invitations`, `sessions`, `relays`, `outbox`,
    /// `settings`.
    #[test]
    fn import_refuses_any_nonempty_table() -> R {
        const ROWS: [(&str, &str); 9] = [
            (
                "identity",
                "INSERT INTO identity (id, secret, fingerprint, created_ms) VALUES (1, x'00', x'00', 0)",
            ),
            (
                "contacts",
                "INSERT INTO contacts (id, iks, fingerprint) VALUES (1, x'00', x'00')",
            ),
            (
                "messages",
                "INSERT INTO messages (contact_id, msg_id, direction, kind, ts_ms, payload) VALUES (1, x'00', 0, 1, 0, x'00')",
            ),
            (
                "prekeys",
                "INSERT INTO prekeys (kind, id, secret) VALUES (1, 1, x'00')",
            ),
            (
                "invitations",
                "INSERT INTO invitations (ld_id, record, expires_ms) VALUES (x'00', x'00', 0)",
            ),
            (
                "sessions",
                "INSERT INTO sessions (session_id, part, ord, data) VALUES (1, 0, 0, x'00')",
            ),
            (
                "relays",
                "INSERT INTO relays (id, relay_ref) VALUES (1, x'00')",
            ),
            (
                "outbox",
                "INSERT INTO outbox (msg_id, contact_id, seq, kind, expire_after, payload, queued_ms, state) VALUES (x'00', 1, 0, 1, 0, x'00', 0, 0)",
            ),
            (
                "settings",
                "INSERT INTO settings (key, value) VALUES ('theme', x'01')",
            ),
        ];
        let counts = |s: &Store| -> Res<Vec<i64>> {
            ROWS.iter()
                .map(|(t, _)| {
                    s.connection_kat()
                        .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                        .map_err(Into::into)
                })
                .collect()
        };
        let (dir, file) = exported("bk-nonempty")?;
        let small = Argon2Params::kat_small();
        for (table, insert) in ROWS {
            let mut store = Store::open(
                &dir.path().join(format!("fresh-{table}")),
                &TestKey::db_key(),
            )?;
            store.connection_kat().execute(insert, [])?;
            let before = counts(&store)?;
            assert_eq!(before.iter().sum::<i64>(), 1, "{table}");
            assert_eq!(
                import_bytes(&mut store, &file, PASS, small, 1),
                Err(Error::Unavailable),
                "{table}"
            );
            assert_eq!(counts(&store)?, before, "{table}: nothing written");
        }
        Ok(())
    }

    /// Killer (A-4e mutant, `resolved`): a bare file name resolves against the current directory (its parent is the
    /// empty path, not a path to canonicalise); a name with a parent keeps it.
    #[test]
    fn bare_file_name_resolves_against_the_current_dir() -> R {
        let here = std::fs::canonicalize(".")?;
        assert_eq!(resolved(Path::new("bare-name"))?, here.join("bare-name"));
        assert_eq!(resolved(Path::new("./bare-name"))?, here.join("bare-name"));
        assert_eq!(resolved(Path::new("..")), Err(Error::Unavailable));
        Ok(())
    }

    /// A4-1-05: the export path is canonicalised before the cloud-folder check (a `..` segment or a symlink cannot
    /// hide or fake a cloud folder), `OneDrive - Org`, `Dropbox_Team` and `Nextcloud-Work` are cloud folders, `Boxes` is
    /// not, an existing file is not overwritten, and the file is written `0600` on Unix.
    #[test]
    fn export_path_hardening() -> R {
        let dir = TempDir::new("bk-path")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        for name in ["OneDrive - X", "Dropbox_Team", "Nextcloud-Work"] {
            let folder = dir.path().join(name);
            std::fs::create_dir_all(&folder)?;
            assert_eq!(
                export(&store, &folder.join("x"), PASS, true, false),
                Err(Error::CloudFolder),
                "{name}"
            );
            assert!(in_cloud_folder(Path::new("/home/u").join(name).as_path()));
        }
        assert!(!in_cloud_folder(Path::new("/home/u/Boxes/x")));
        assert!(!in_cloud_folder(Path::new("/home/u/Boxed-in/x")));
        let (dropbox, safe) = (dir.path().join("Dropbox"), dir.path().join("safe"));
        std::fs::create_dir_all(&dropbox)?;
        std::fs::create_dir_all(&safe)?;
        let dotted = dropbox.join("..").join("safe").join("x");
        export(&store, &dotted, PASS, true, false)?;
        let written = safe.join("x");
        assert!(written.is_file(), "written beside Dropbox, not into it");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&written)?.permissions().mode() & 0o777,
                0o600
            );
        }
        let before = std::fs::read(&written)?;
        assert_eq!(
            export(&store, &written, PASS, true, false),
            Err(Error::Unavailable),
            "an existing file is not overwritten"
        );
        assert_eq!(std::fs::read(&written)?, before);
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&dropbox, &link)?;
            assert_eq!(
                export(&store, &link.join("y"), PASS, true, false),
                Err(Error::CloudFolder),
                "a symlink into a cloud folder"
            );
            assert!(!dropbox.join("y").exists());
        }
        Ok(())
    }

    /// Whether a product source line names `backup::export` (not `export_kat` or another item).
    fn names_export(line: &str) -> bool {
        line.contains("backup::")
            && line.match_indices("export").any(|(at, _)| {
                line.get(at.saturating_add(6)..)
                    .and_then(|rest| rest.chars().next())
                    .is_none_or(|c| !(c == '_' || c.is_ascii_alphanumeric()))
            })
    }

    /// BK-07 [O-01] (CS-3.5: never automatic): a scan of every crate's product source (test modules excluded,
    /// CRLF-normalised) finds no line naming `backup::export` outside the allowed set — the client's `Api` handler
    /// (`secmp-client-core/src/api.rs`, Phase B), so no timer or startup path calls it. In A-4 there is no caller at
    /// all; Phase B re-runs this test unchanged.
    #[test]
    fn never_automatic() -> R {
        const ALLOWED: &[&str] = &["secmp-client-core/src/api.rs"];
        assert!(names_export(
            "let _ = secmp_store::backup::export(&s, p, b\"x\", true, false);"
        ));
        assert!(names_export("use secmp_store::backup::{export, import};"));
        assert!(!names_export(
            "secmp_store::backup::export_kat(&s, p, b\"x\", small)?;"
        ));
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut callers = Vec::new();
        let mut files = 0_usize;
        let mut stack: Vec<std::path::PathBuf> = std::fs::read_dir(&crates)?
            .map(|e| e.map(|e| e.path().join("src")))
            .collect::<std::io::Result<_>>()?;
        while let Some(d) = stack.pop() {
            if !d.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(&d)? {
                let path = entry?.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs")
                    || path.ends_with("secmp-store/src/backup.rs")
                {
                    continue;
                }
                files = files.saturating_add(1);
                let text = std::fs::read_to_string(&path)?.replace("\r\n", "\n");
                let product = text
                    .split("#[cfg(test)]\nmod tests")
                    .next()
                    .unwrap_or_default();
                let rel = path
                    .strip_prefix(&crates)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if product.lines().any(names_export) {
                    callers.push(rel);
                }
            }
        }
        assert!(files > 100, "{files} source files scanned");
        assert!(
            callers.iter().all(|c| ALLOWED.contains(&c.as_str())),
            "{callers:?}"
        );
        assert_eq!(callers, Vec::<String>::new(), "A-4: no caller");
        Ok(())
    }

    /// Killers (A-4 mutants, `Contents::of`, `Contents::encode`): an identity section of the right length with version 2,
    /// a contact name of 65 bytes and an `IKSPublic` one byte short are refused at export (`Unavailable`); a 64-byte name
    /// is exported.
    #[test]
    fn export_refuses_malformed_rows() -> R {
        let dir = TempDir::new("bk-k1")?;
        let path = dir.path().join("export");
        let iks = peer_iks(1)?;
        let profile = Profile::new("Bob", None)?.encode()?;
        let case = |label: &str, identity: &[u8], iks: &[u8], name: &str| -> Res<Result<()>> {
            let mut store = Store::open(&dir.path().join(label), &TestKey::db_key())?;
            store.txn(|tx| {
                put_identity(tx, 1, identity, b"fp", 1)?;
                let contact = Contact {
                    id: 1,
                    iks,
                    fingerprint: b"fp",
                    display_name: Some(name),
                    verified: false,
                    routes: None,
                    queues: None,
                    state: 0,
                    profile: Some(&profile),
                };
                put_contact(tx, &contact)
            })?;
            Ok(export_kat(&store, &path, PASS, Argon2Params::kat_small()))
        };
        let mut v2 = identity();
        if let Some(b) = v2.first_mut() {
            *b = 2;
        }
        let short = iks.get(1..).unwrap_or_default();
        assert_eq!(case("v2", &v2, &iks, "Bob")?, Err(Error::Unavailable));
        assert_eq!(
            case("name65", &identity(), &iks, &"n".repeat(65))?,
            Err(Error::Unavailable)
        );
        assert_eq!(
            case("iks", &identity(), short, "Bob")?,
            Err(Error::Unavailable)
        );
        assert_eq!(case("name64", &identity(), &iks, &"n".repeat(64))?, Ok(()));
        Ok(())
    }

    /// Killers (A-4 mutants, `decode`, `Cursor::finish`): a body whose identity section has version 2, whose contacts
    /// section carries a trailing byte, or whose contact name is 65 bytes is refused (`Unlock`); a 64-byte name decodes.
    #[test]
    fn decode_refuses_malformed_sections() -> R {
        let iks = peer_iks(1)?;
        let profile = Profile::new("Bob", None)?.encode()?;
        let contacts = |name_len: usize, trailing: bool| {
            let mut c = 1_u32.to_be_bytes().to_vec();
            c.extend_from_slice(&iks);
            c.push(1);
            c.extend_from_slice(&profile);
            c.push(u8::try_from(name_len).unwrap_or(0));
            c.extend(std::iter::repeat_n(b'n', name_len));
            if trailing {
                c.push(0);
            }
            c
        };
        let (settings, messages) = (0_u16.to_be_bytes(), 0_u32.to_be_bytes());
        let body = |identity: &[u8], contacts: &[u8]| {
            let lens = [
                identity.len(),
                contacts.len(),
                settings.len(),
                messages.len(),
            ];
            ([identity, contacts, &settings, &messages].concat(), lens)
        };
        let (ok, lens) = body(&identity(), &contacts(64, false));
        let names: Vec<usize> = decode(&ok, lens)?
            .contacts
            .iter()
            .map(|c| c.local_name.len())
            .collect();
        assert_eq!(names, [64]);
        let mut v2 = identity();
        if let Some(b) = v2.first_mut() {
            *b = 2;
        }
        for (name, (b, lens)) in [
            ("version 2", body(&v2, &contacts(0, false))),
            ("trailing byte", body(&identity(), &contacts(3, true))),
            ("name of 65", body(&identity(), &contacts(65, false))),
        ] {
            assert_eq!(decode(&b, lens).err(), Some(Error::Unlock), "{name}");
        }
        Ok(())
    }

    /// Killer (A-4 mutant, `parse`): a file whose `params` differ (version right) or whose version differs (`params`
    /// right) is refused before the KDF — no Argon2id call (ADR-053 item 2 applied to item 6); the file itself takes one.
    #[test]
    fn header_checks_precede_the_kdf() -> R {
        let (_dir, file) = exported("bk-k3")?;
        let flip = |at: usize| {
            let mut f = file.clone();
            if let Some(b) = f.get_mut(at) {
                *b ^= 1;
            }
            f
        };
        for (name, f) in [("params", flip(30 + 11)), ("version", flip(13))] {
            crate::kat::reset_counters();
            assert_eq!(
                open_export_kat(&f, PASS).err(),
                Some(Error::Unlock),
                "{name}"
            );
            assert_eq!(crate::kat::argon2_calls(), 0, "{name}");
        }
        crate::kat::reset_counters();
        assert!(open_export_kat(&file, PASS).is_ok());
        assert_eq!(crate::kat::argon2_calls(), 1);
        Ok(())
    }

    /// Killers (A-4 mutants, the `kat` entry points of the fuzz target `backup_import`): `seal_file_kat` seals a body that
    /// `open_body_kat` gives back and `open_export_kat` decodes, and `encode_body_kat` re-encodes it to the same bytes.
    #[test]
    fn fuzz_entry_points_round_trip() -> R {
        let (_dir, file) = exported("bk-k4")?;
        let body = open_body_kat(&file, PASS)?;
        let again = seal_file_kat(PASS, &table(&file), &body)?;
        assert_eq!(again.len(), file.len());
        assert_eq!(open_body_kat(&again, PASS)?.as_slice(), body.as_slice());
        let contents = open_export_kat(&again, PASS)?;
        assert_eq!(encode_body_kat(&contents)?.as_slice(), body.as_slice());
        Ok(())
    }

    /// Killers (A-4 mutants, `import`, `identity_fingerprint`, `import_bytes`): `import` reads the file at a path with the
    /// profile parameters; the restored identity row carries the fingerprint of its seeds; a contact's name is kept and
    /// an empty name is stored as none.
    #[test]
    fn import_restores_fingerprint_and_names() -> R {
        let dir = TempDir::new("bk-k5")?;
        let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
        populate(&mut store)?;
        let path = dir.path().join("export");
        export(&store, &path, PASS, true, true)?;
        let mut fresh = Store::open(&dir.path().join("restored"), &TestKey::db_key())?;
        import(&mut fresh, &path, PASS, 9)?;
        let fp: Vec<u8> = fresh.connection_kat().query_row(
            "SELECT fingerprint FROM identity WHERE id = 1",
            [],
            |r| r.get(0),
        )?;
        let own = IdentityKeys::from_parts(
            HybridSigningKey::from_seeds(&[0x11; 32], &[0x22; 32])?,
            IkDhSecret::from_bytes(&[0x33; 32])?,
        )?;
        assert_eq!(fp, own.fingerprint()?.to_vec());
        let names: Vec<Option<String>> = fresh
            .contacts()?
            .into_iter()
            .map(|c| c.display_name)
            .collect();
        assert_eq!(names, [Some("Bobby".to_owned()), None]);
        Ok(())
    }
}
