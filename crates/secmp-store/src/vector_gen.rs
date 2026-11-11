// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Rust side of the `store` vectors (SCHEMA §4.12, `vectors/SCHEMA-4.12-store.md`): every case built through the
//! store's own code with derandomised entropy; written to `vectors/rust/store.json` for `cargo xtask vectors`.
//! Test-only (feature `kat`); reads no vector file to generate.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use secmp_crypto::{Caead, HybridSigningKey, Label, LockedSecret, Nonce24, VectorStream};
use secmp_proto::Encode;
use secmp_proto::prekeys::{IdentityKeys, IkDhSecret};

use crate::backup::{self, MAGIC};
use crate::error::{Error, Result};
#[cfg(feature = "kat")]
use crate::kat::TestKey;
use crate::kat::{TempDir, fixed_random};
use crate::keys::{Table, TableKeys, derive};
use crate::profile::put_identity;
use crate::seal::{self, KeyPart, row_key};
use crate::secrets::StoreKey;
use crate::store::Store;
use crate::wrap::{self, Argon2Params, WRAP_FILE};

type R = core::result::Result<(), Box<dyn std::error::Error>>;
type Res<T> = core::result::Result<T, Box<dyn std::error::Error>>;

const SUITE: &str = "store";
const PROFILE: Argon2Params = Argon2Params::PROFILE;
const ALT: Argon2Params = Argon2Params {
    m_kib: 65_536,
    t: 3,
    p: 4,
};
const PASS_1: &[u8] = "correct horse battery staple".as_bytes();
const PASS_2: &str = "P\u{e4}ssw\u{f6}rt-\u{3a9}";
const PASS_WRONG: &[u8] = "correct horse battery stapler".as_bytes();
const PASS_BK: &str = "backup-\u{3a9} 2026";
const PASS_BK_WRONG: &str = "backup-\u{3a9} 2027";
const VER: u8 = 1;
const TS_MS: u64 = 1_800_000_000_000;

/// A JSON value of the vector file (SCHEMA §1).
#[derive(Clone)]
pub(crate) enum J {
    Hex(Vec<u8>),
    Str(String),
    Int(i64),
    Arr(Vec<J>),
    Obj(BTreeMap<String, J>),
}

/// SCHEMA §1 canonical form: sorted keys, `,` and `:` without spaces, lowercase hex, decimal integers.
pub(crate) fn canonical(j: &J) -> Res<String> {
    let mut out = String::new();
    write_json(j, &mut out)?;
    Ok(out)
}

fn write_json(j: &J, out: &mut String) -> R {
    match j {
        J::Hex(b) => {
            out.push('"');
            for x in b {
                write!(out, "{x:02x}")?;
            }
            out.push('"');
        }
        J::Str(t) => {
            if t.bytes()
                .any(|c| !(0x20..=0x7e).contains(&c) || c == b'"' || c == b'\\')
            {
                return Err("a string outside the ASCII subset the schema allows".into());
            }
            out.push('"');
            out.push_str(t);
            out.push('"');
        }
        J::Int(i) => write!(out, "{i}")?,
        J::Arr(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out)?;
            }
            out.push(']');
        }
        J::Obj(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&J::Str(k.clone()), out)?;
                out.push(':');
                write_json(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> J {
    J::Hex(b.to_vec())
}

fn text(s: &str) -> J {
    J::Str(s.to_owned())
}

fn obj(items: Vec<(&str, J)>) -> J {
    J::Obj(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn id(i: u32) -> String {
    format!("{SUITE}-{i:04}")
}

/// A positive case (`from` for the `seal` cases).
fn positive(i: u32, op: &str, inputs: J, outputs: J, from: Option<u32>) -> J {
    let mut items = vec![
        ("id", J::Str(id(i))),
        ("op", text(op)),
        ("inputs", inputs),
        ("outputs", outputs),
    ];
    if let Some(f) = from {
        items.push(("from", J::Str(id(f))));
    }
    obj(items)
}

/// A reject case: no `outputs`, `from`, `manipulation`, `"expect": "reject"`.
fn reject(i: u32, op: &str, inputs: J, from: u32, manipulation: &str) -> J {
    obj(vec![
        ("id", J::Str(id(i))),
        ("op", text(op)),
        ("inputs", inputs),
        ("from", J::Str(id(from))),
        ("manipulation", text(manipulation)),
        ("expect", text("reject")),
    ])
}

/// The product refused with exactly `want`.
fn refused<T>(r: &Result<T>, want: Error) -> R {
    match r {
        Err(e) if *e == want => Ok(()),
        Err(_) => Err("a reject case failed with another error".into()),
        Ok(_) => Err("a reject case was accepted".into()),
    }
}

fn locked(b: &[u8; 32]) -> Res<LockedSecret<32>> {
    Ok(LockedSecret::<32>::from_slice(b)?)
}

fn nonce(n: &[u8; 24]) -> Nonce24 {
    Nonce24::from_bytes_kat(*n)
}

/// Case 1: the ten keys of one `mk` (ADR-053 items 3, 4).
pub(crate) fn keys_case() -> Res<J> {
    let mk = VectorStream::new(SUITE, 1).arr::<32>();
    let lm = locked(&mk)?;
    let tables = TableKeys::derive(&lm)?;
    let mut outs = BTreeMap::new();
    for t in Table::ALL {
        let label = t.label().as_str();
        let name = label.strip_prefix("SecMP-STORE/1 ").ok_or("label")?;
        outs.insert(format!("k_{name}"), hex(tables.get(t).expose_secret()));
    }
    let k_db = derive(&lm, Label::StoreDb)?;
    outs.insert("k_db".to_owned(), hex(k_db.locked().expose_secret()));
    Ok(positive(
        1,
        "keys",
        obj(vec![("mk", hex(&mk))]),
        J::Obj(outs),
        None,
    ))
}

/// Cases 2–7: the profile wrap and its rejects (ADR-053 items 1, 2).
fn wrap_cases() -> Res<Vec<J>> {
    let mut out = Vec::new();
    let mut first = None;
    for (i, pass) in [(2_u32, PASS_1), (3, PASS_2.as_bytes())] {
        let mut st = VectorStream::new(SUITE, i);
        let (salt, n, mk) = (st.arr::<16>(), st.arr::<24>(), st.arr::<32>());
        let dir = TempDir::new("vec-wrap")?;
        fixed_random(&[&mk[..], &salt, &n].concat());
        wrap::create_kat(dir.path(), pass, PROFILE)?;
        let wrap_bytes = std::fs::read(dir.path().join(WRAP_FILE))?;
        let kek = wrap::kek_kat(pass, &salt, PROFILE)?;
        out.push(positive(
            i,
            "wrap",
            obj(vec![
                ("passphrase", hex(pass)),
                ("salt", hex(&salt)),
                ("n", hex(&n)),
                ("mk", hex(&mk)),
            ]),
            obj(vec![
                ("kek", hex(kek.locked().expose_secret())),
                ("wrap", hex(&wrap_bytes)),
            ]),
            None,
        ));
        if i == 2 {
            first = Some((salt, n, mk, wrap_bytes, kek));
        }
    }
    let (salt, n, mk, wrap_bytes, kek2) = first.ok_or("case 2")?;
    let ad = |ver: u8, enc: &[u8; 12]| [Label::StoreWrap.as_bytes(), &[ver], &salt, enc].concat();
    let honest = |ver: u8, params: Argon2Params, kek: &LockedSecret<32>| -> Res<Vec<u8>> {
        let enc = params.encode();
        let sealed = Caead::seal_locked(kek, nonce(&n), &ad(ver, &enc), &mk)?;
        Ok([&[ver][..], &salt, &enc, &n, &sealed].concat())
    };
    let kek_alt = wrap::kek_kat(PASS_1, &salt, ALT)?;
    let mut short = wrap_bytes.clone();
    short.pop();
    let rejects = [
        ("wrong-passphrase", PASS_WRONG, wrap_bytes.clone()),
        ("ver=02", PASS_1, honest(2, PROFILE, kek2.locked())?),
        (
            "params=65536,3,4",
            PASS_1,
            honest(VER, ALT, kek_alt.locked())?,
        ),
        ("drop-last", PASS_1, short),
    ];
    for (i, (manipulation, pass, blob)) in (4_u32..).zip(rejects) {
        refused(&wrap::open_kat(&blob, pass, PROFILE), Error::Unlock)?;
        out.push(reject(
            i,
            "wrap-reject",
            obj(vec![("passphrase", hex(pass)), ("wrap", hex(&blob))]),
            2,
            manipulation,
        ));
    }
    Ok(out)
}

/// A part of a primary key.
enum Part {
    Int(i64),
    Bytes(Vec<u8>),
}

fn key_parts(parts: &[Part]) -> Vec<KeyPart<'_>> {
    parts
        .iter()
        .map(|p| match p {
            Part::Int(v) => KeyPart::Int(*v),
            Part::Bytes(b) => KeyPart::Bytes(b),
        })
        .collect()
}

fn parts_json(parts: &[Part]) -> J {
    J::Arr(
        parts
            .iter()
            .map(|p| match p {
                Part::Int(v) => obj(vec![("int", J::Int(*v))]),
                Part::Bytes(b) => obj(vec![("bytes", hex(b))]),
            })
            .collect(),
    )
}

fn seal_inputs(
    k_t: &[u8; 32],
    table: Table,
    column: &str,
    parts: &[Part],
    rec: Option<&[u8]>,
) -> Vec<(&'static str, J)> {
    let mut items = vec![
        ("k_t", hex(k_t)),
        ("label", text(table.label().as_str())),
        ("column", text(column)),
        ("row_key_parts", parts_json(parts)),
    ];
    if let Some(r) = rec {
        items.push(("rec", hex(r)));
    }
    items
}

/// The sealed columns of cases 8–11: (case, table, column, shape of the row key, record length).
type SealSpec = (u32, Table, &'static str, usize, usize);

const SEAL_SPECS: [SealSpec; 4] = [
    (8, Table::Contacts, "routes", 0, 48),
    (9, Table::Invitations, "record", 1, 33),
    (10, Table::Prekeys, "secret", 2, 64),
    (11, Table::Sessions, "data", 3, 80),
];

/// Cases 8–11: the record seal (ADR-053 item 5, Amendment 1).
fn seal_positive(tables: &TableKeys) -> Res<(Vec<J>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut first = None;
    for (i, table, column, shape, rlen) in SEAL_SPECS {
        let mut st = VectorStream::new(SUITE, i);
        let n = st.arr::<24>();
        let parts = match shape {
            0 => vec![Part::Int(7)],
            1 => vec![Part::Bytes(st.take(16))],
            2 => vec![Part::Int(1), Part::Int(42)],
            _ => vec![Part::Int(3), Part::Int(5), Part::Int(0)],
        };
        let record = st.take(rlen);
        let rk = row_key(&key_parts(&parts))?;
        let key = tables.get(table);
        fixed_random(&n);
        let rec = seal::seal(key, table, column, &rk, &record)?;
        let opened = seal::open(key, table, column, &rk, &rec)?;
        if opened.as_slice() != record.as_slice() {
            return Err("a sealed record does not open to its plaintext".into());
        }
        let ad = [
            table.label().as_bytes(),
            &[u8::try_from(column.len())?],
            column.as_bytes(),
            &rk,
        ]
        .concat();
        let mut ins = seal_inputs(key.expose_secret(), table, column, &parts, None);
        ins.push(("n", hex(&n)));
        ins.push(("record", hex(&record)));
        let outs = vec![("row_key", hex(&rk)), ("ad", hex(&ad)), ("rec", hex(&rec))];
        out.push(positive(i, "seal", obj(ins), obj(outs), Some(1)));
        if i == 8 {
            first = Some(rec);
        }
    }
    Ok((out, first.ok_or("case 8")?))
}

/// A place the record of case 8 is opened at.
struct Attempt<'a> {
    case: u32,
    manipulation: &'static str,
    key: &'a LockedSecret<32>,
    /// The table whose label goes into the AD.
    table: Table,
    column: &'static str,
    parts: Vec<Part>,
}

/// Cases 12–15 and 20: the record rejects (`rec8` is the record of case 8).
fn seal_rejects(tables: &TableKeys, rec8: &[u8]) -> Res<Vec<J>> {
    let (contacts, sessions) = (tables.get(Table::Contacts), tables.get(Table::Sessions));
    let at = |case, manipulation, key, table, column, parts| Attempt {
        case,
        manipulation,
        key,
        table,
        column,
        parts,
    };
    let attempts = [
        at(
            12,
            "column=queues",
            contacts,
            Table::Contacts,
            "queues",
            vec![Part::Int(7)],
        ),
        at(
            13,
            "row=8",
            contacts,
            Table::Contacts,
            "routes",
            vec![Part::Int(8)],
        ),
        at(
            14,
            "table=sessions",
            sessions,
            Table::Sessions,
            "routes",
            vec![Part::Int(7)],
        ),
        at(
            20,
            "label=sessions",
            contacts,
            Table::Sessions,
            "routes",
            vec![Part::Int(7)],
        ),
    ];
    let mut out = Vec::new();
    for a in attempts {
        let row = row_key(&key_parts(&a.parts))?;
        refused(
            &seal::open(a.key, a.table, a.column, &row, rec8),
            Error::Unavailable,
        )?;
        let ins = seal_inputs(
            a.key.expose_secret(),
            a.table,
            a.column,
            &a.parts,
            Some(rec8),
        );
        out.push(reject(a.case, "seal-reject", obj(ins), 8, a.manipulation));
    }
    refused(&row_key(&[KeyPart::Int(-1)]), Error::Unavailable)?;
    let ins = seal_inputs(
        contacts.expose_secret(),
        Table::Contacts,
        "routes",
        &[Part::Int(-1)],
        None,
    );
    out.push(reject(
        15,
        "seal-reject",
        obj(ins),
        8,
        "row=-1 (not encodable)",
    ));
    Ok(out)
}

/// Cases 8–15 and 20.
fn seal_cases() -> Res<Vec<J>> {
    let mk = VectorStream::new(SUITE, 1).arr::<32>();
    let tables = TableKeys::derive(&locked(&mk)?)?;
    let (mut out, rec8) = seal_positive(&tables)?;
    out.extend(seal_rejects(&tables, &rec8)?);
    Ok(out)
}

/// The honest ingredients of case 16 and the means to craft files around them.
struct Backup {
    salt: [u8; 16],
    n_prime: [u8; 24],
    mk_bk: [u8; 32],
    n: [u8; 24],
    identity: Vec<u8>,
}

impl Backup {
    fn draw() -> Self {
        let mut st = VectorStream::new(SUITE, 16);
        let (salt, n_prime, mk_bk, n) = (
            st.arr::<16>(),
            st.arr::<24>(),
            st.arr::<32>(),
            st.arr::<24>(),
        );
        let identity = [&[VER][..], &st.take(96)].concat();
        Self {
            salt,
            n_prime,
            mk_bk,
            n,
            identity,
        }
    }

    /// `magic ‖ header ‖ N ‖ Seal(K_bk, N, "SecMP-STORE/1 backup" ‖ header, body)` with a `bwrap` sealed under `kek` and
    /// `bwrap_label` (ADR-053 item 6); the section table follows `sections`.
    fn craft(
        &self,
        params: Argon2Params,
        kek: &LockedSecret<32>,
        bwrap_label: Label,
        sections: &[&[u8]; 4],
    ) -> Res<Vec<u8>> {
        let enc = params.encode();
        let ad_w = [bwrap_label.as_bytes(), &[VER], &self.salt, &enc].concat();
        let wrapped = Caead::seal_locked(kek, nonce(&self.n_prime), &ad_w, &self.mk_bk)?;
        let mut header = [&[VER][..], &self.salt, &enc, &self.n_prime, &wrapped].concat();
        header.push(4);
        for (tag, s) in (1_u8..).zip(sections) {
            header.push(tag);
            header.extend_from_slice(&u32::try_from(s.len())?.to_be_bytes());
        }
        let k_bk = derive(&locked(&self.mk_bk)?, Label::StoreBackup)?;
        let ad = [Label::StoreBackup.as_bytes(), &header].concat();
        let body = sections.concat();
        let sealed = Caead::seal_locked(k_bk.locked(), nonce(&self.n), &ad, &body)?;
        Ok([&MAGIC[..], &header, &self.n, &sealed].concat())
    }
}

/// An empty profile store in `dir`.
#[cfg(feature = "kat")]
fn fresh_store(dir: &TempDir, name: &str) -> Res<Store> {
    Ok(Store::open(&dir.path().join(name), &TestKey::db_key())?)
}

/// `import_kat` of `file` into a fresh store (`PROFILE` accepted).
fn import(dir: &TempDir, name: &str, pass: &[u8], file: &[u8]) -> Result<()> {
    let path = dir.path().join(format!("{name}.secmpbackup"));
    std::fs::write(&path, file).map_err(|_| Error::Unavailable)?;
    let mut store = fresh_store(dir, name).map_err(|_| Error::Unavailable)?;
    backup::import_kat(&mut store, &path, pass, PROFILE, 1)
}

fn iks_public() -> Res<Vec<u8>> {
    let sig = HybridSigningKey::from_seeds(&[1; 32], &[2; 32])?;
    let keys = IdentityKeys::from_parts(sig, IkDhSecret::from_bytes(&[3; 32])?)?;
    Ok(keys.public().encode()?.to_vec())
}

/// The contacts section of one contact; `profile` is its `Profile` bytes.
fn contact_section(profile: &[u8]) -> Res<Vec<u8>> {
    let contact = [&iks_public()?[..], &[1], profile, &[3], b"Bob"].concat();
    Ok([&1_u32.to_be_bytes()[..], &contact].concat())
}

/// The messages section of one message.
fn message_section(index: u32, kind: u8) -> Vec<u8> {
    [
        &1_u32.to_be_bytes()[..],
        &index.to_be_bytes(),
        &[1],
        &TS_MS.to_be_bytes(),
        &[7; 16],
        &[kind],
        &[0_u8; 4],
        &[0_u8, 2],
        b"hi",
    ]
    .concat()
}

/// The honest export of case 16: its case, the file and the KEK; with `verify` the product imports the file.
fn export_case(b: &Backup, dir: &TempDir, verify: bool) -> Res<(J, Vec<u8>, StoreKey)> {
    let pass = PASS_BK.as_bytes();
    let mut store = fresh_store(dir, "profile")?;
    store.txn(|tx| put_identity(tx, 1, &b.identity, b"vector fingerprint", 1))?;
    fixed_random(&[&b.salt[..], &b.mk_bk, &b.n_prime, &b.n].concat());
    let path = dir.path().join("export.secmpbackup");
    backup::export_kat(&store, &path, pass, PROFILE)?;
    let file = std::fs::read(&path)?;
    let header = file.get(13..167).ok_or("header")?;
    let bwrap = file.get(42..146).ok_or("bwrap")?;
    let kek_bk = wrap::kek_kat(pass, &b.salt, PROFILE)?;
    let k_bk = derive(&locked(&b.mk_bk)?, Label::StoreBackup)?;
    let body = [b.identity.as_slice(), &[0_u8; 4], &[0_u8; 2], &[0_u8; 4]].concat();
    let ins = vec![
        ("passphrase", hex(pass)),
        ("salt", hex(&b.salt)),
        ("n_prime", hex(&b.n_prime)),
        ("mk_bk", hex(&b.mk_bk)),
        ("n", hex(&b.n)),
        ("identity", hex(&b.identity)),
    ];
    let outs = vec![
        ("kek_bk", hex(kek_bk.locked().expose_secret())),
        ("bwrap", hex(bwrap)),
        ("k_bk", hex(k_bk.locked().expose_secret())),
        ("header", hex(header)),
        ("body", hex(&body)),
        ("file", hex(&file)),
    ];
    if verify {
        import(dir, "import-16", pass, &file)?;
    }
    let case = positive(16, "backup", obj(ins), obj(outs), None);
    Ok((case, file, kek_bk))
}

/// The contacts, settings and messages sections of a reject case (cases 21–26).
type BodyCase = (u32, &'static str, [Vec<u8>; 3]);

/// Cases 21–26: honest sections that only Amendment 2 (21, 22) or Amendment 3 (23–26) rejects.
fn body_cases() -> Res<Vec<BodyCase>> {
    let (zero4, zero2) = (vec![0_u8; 4], vec![0_u8; 2]);
    let settings = |entries: &[&[u8]]| -> Vec<u8> {
        let count = u16::try_from(entries.len()).unwrap_or(0);
        [&count.to_be_bytes()[..], &entries.concat()].concat()
    };
    let retention = [
        &[0x0e][..],
        b"retention_days",
        &[0, 4],
        &30_u32.to_be_bytes(),
    ]
    .concat();
    let profile = [&[4][..], b"peer", &[0]].concat();
    let profile_flag = [&[4][..], b"peer", &[2]].concat();
    let mode = [&[4][..], b"mode", &[0, 4, 0, 0, 0, 1]].concat();
    let short = [&[0x0e][..], b"retention_days", &[0, 3, 0, 0, 0x1e]].concat();
    Ok(vec![
        (
            21,
            "settings-key=mode",
            [zero4.clone(), settings(&[&mode]), zero4.clone()],
        ),
        (
            22,
            "retention_days-len=3",
            [zero4.clone(), settings(&[&short]), zero4.clone()],
        ),
        (
            23,
            "settings-key-twice",
            [
                zero4.clone(),
                settings(&[&retention, &retention]),
                zero4.clone(),
            ],
        ),
        (
            24,
            "contact_index=1",
            [
                contact_section(&profile)?,
                zero2.clone(),
                message_section(1, 1),
            ],
        ),
        (
            25,
            "profile-avatar-flag=2",
            [contact_section(&profile_flag)?, zero2.clone(), zero4],
        ),
        (
            26,
            "view-once",
            [contact_section(&profile)?, zero2, message_section(0, 3)],
        ),
    ])
}

/// Cases 16–19 and 21–26: the backup file and its rejects (ADR-053 item 6, Amendments 2 and 3). With `verify` the
/// product also imports (case 16) or refuses (the rest) each file: one `PROFILE` Argon2id per check.
pub(crate) fn backup_cases(verify: bool) -> Res<Vec<J>> {
    let b = Backup::draw();
    let pass = PASS_BK.as_bytes();
    let dir = TempDir::new("vec-backup")?;
    let (case16, file, kek_bk) = export_case(&b, &dir, verify)?;
    let kek_alt = wrap::kek_kat(pass, &b.salt, ALT)?;
    let id_sec = b.identity.as_slice();
    let ok: [&[u8]; 4] = [id_sec, &[0; 4], &[0; 2], &[0; 4]];
    let mut rejects: Vec<(u32, &str, &[u8], Vec<u8>)> = vec![
        (17, "wrong-passphrase", PASS_BK_WRONG.as_bytes(), file),
        (
            18,
            "params=65536,3,4",
            pass,
            b.craft(ALT, kek_alt.locked(), Label::StoreBwrap, &ok)?,
        ),
        (
            19,
            "bwrap-label=wrap",
            pass,
            b.craft(PROFILE, kek_bk.locked(), Label::StoreWrap, &ok)?,
        ),
    ];
    for (i, manipulation, [contacts, settings, messages]) in &body_cases()? {
        let secs = [id_sec, contacts, settings, messages];
        let f = b.craft(PROFILE, kek_bk.locked(), Label::StoreBwrap, &secs)?;
        rejects.push((*i, manipulation, pass, f));
    }
    let mut out = vec![case16];
    for (i, manipulation, p, f) in rejects {
        if verify {
            refused(&import(&dir, &format!("import-{i}"), p, &f), Error::Unlock)?;
        }
        let ins = vec![("passphrase", hex(p)), ("file", hex(&f))];
        out.push(reject(i, "backup-reject", obj(ins), 16, manipulation));
    }
    Ok(out)
}

fn id_of(j: &J) -> String {
    match j {
        J::Obj(m) => match m.get("id") {
            Some(J::Str(s)) => s.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// Every case of the suite, sorted by id (the product checks of `backup_cases` are off: `backup_cases(false)`).
pub(crate) fn cases() -> Res<Vec<J>> {
    let mut all = vec![keys_case()?];
    all.extend(wrap_cases()?);
    all.extend(seal_cases()?);
    all.extend(backup_cases(false)?);
    all.sort_by_key(id_of);
    Ok(all)
}

fn document_of(cases: Vec<J>, generator: &str) -> J {
    obj(vec![
        ("schema", J::Int(8)),
        ("suite", text(SUITE)),
        ("spec", text("SecMP/1 rev 2.7")),
        ("generator", text(generator)),
        ("cases", J::Arr(cases)),
    ])
}

fn repo_path(rel: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// A file of the repository, line ends normalised.
pub(crate) fn repo_file(rel: &str) -> Res<String> {
    Ok(std::fs::read_to_string(repo_path(rel))?.replace("\r\n", "\n"))
}

/// Writes `vectors/rust/store.json` and checks it against `vectors/ref/store.json`, case by case and as a whole.
#[test]
fn rust_store_vectors_equal_the_reference_file() -> R {
    let cases = cases()?;
    let out = repo_path("vectors/rust/store.json");
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&out, canonical(&document_of(cases.clone(), "secmp-rust"))?)?;
    let theirs = repo_file("vectors/ref/store.json")?;
    for case in &cases {
        assert!(
            theirs.contains(&canonical(case)?),
            "{} differs from vectors/ref/store.json",
            id_of(case)
        );
    }
    assert_eq!(canonical(&document_of(cases, "ref-python"))?, theirs);
    Ok(())
}
