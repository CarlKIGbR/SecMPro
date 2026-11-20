// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 FO-03 (CS-3.5 `docs/04:56`): the forensic scan of a backup export file. The source profile holds the
//! input of BK-01 (`secmp-store` `backup::tests::contents_whitelist`: the identity, a contact, settings, a received and
//! a sent message, a session, prekeys, the outbox, a relay and an invitation) with the canaries of the Conventions
//! (TEST-SPEC-M7 `:55-57`) placed in it; the export file (`kat_small`) is scanned with the FO-01a scan
//! (`secmp_store::kat::scan_dir`: raw bytes, and substrings ≥ 8 B inside printable runs ≥ 4 B).
//!
//! M7-C4 (Q292): FO-01a with FO-02 folded in. Two store-backed parties on the `VirtualDriver` (Balanced) chat 25 rounds
//! carrying canaries; the profile directories are scanned twice, as an `abort` leaves them (every file at an idle point,
//! WAL checkpoints off, `lock` not copied) and after a clean close; FO-02: the whole run happens in a child process whose
//! `HOME`, `TMPDIR`, `TMP`, `TEMP` and `XDG_*` point to empty directories, which stay empty; the Tor directories are
//! the profile's; deleting the profile directory removes everything. A failure message carries labels, never a needle.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use secmp_client_core::api::{ContactId, Event, Request, Response};
use secmp_client_core::scheduler::params::Mode;
use secmp_crypto::{HybridSigningKey, SecretBytes, Zeroizing, kdf_ck};
use secmp_proto::Encode;
use secmp_proto::prekeys::{IdentityKeys, IkDhSecret, fingerprint_of};
use secmp_proto::wire::inv::Profile;
use secmp_store::Store;
use secmp_store::backup::export_kat;
use secmp_store::contacts::{Contact, STATE_ACTIVE, put_contact};
use secmp_store::kat::{TempDir, TestKey, child_role, measure_writes, run_child, scan_dir};
use secmp_store::keys::Table;
use secmp_store::messages::{Direction, NewMessage};
use secmp_store::outbox::{OutboxRow, state};
use secmp_store::profile::{insert_invitation, insert_prekey, put_identity, put_relay};
use secmp_store::sessions::{
    SessionRows, TRUST_VERIFIED, insert_skipped, put_fixed, put_inbox, update_trust,
};
use secmp_store::wrap::{Argon2Params, WRAP_FILE, kek_kat, unlock_kat};
use secmp_testkit::harness::VirtualDriver;

use super::m7_world::{
    PASS as PROFILE_PASS, Party, add_party_mode, contact_ids, driver, hub, invite_pair,
};

type R = core::result::Result<(), Box<dyn std::error::Error>>;

/// The backup passphrase (itself a canary).
const PASS: &str = "Backup-Passphrase-Canary-77";
/// The message text canary.
const MSG: &str = "CANARY-MSG-0123456789abcdef";
/// The contact display name canary.
const NAME: &str = "Zebulon-Canary-1a2b3c4d";
/// The own name canary (a setting of the profile).
const OWN: &str = "Ownname-Canary-5e6f7a8b";
/// The invitation `link_key` canary (in the invitation record, which the export does not hold).
const LINK_KEY: [u8; 32] = [0xc7; 32];
/// The identity seeds: Ed25519, ML-DSA-65, X25519.
const SEEDS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];

/// `s` as UTF-16LE.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Lower- and upper-case hex of `b`.
fn hex(b: &[u8]) -> [Vec<u8>; 2] {
    let lower = b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    });
    let upper = lower.to_uppercase();
    [lower.into_bytes(), upper.into_bytes()]
}

/// The identity of `seeds` (Ed25519, ML-DSA-65, X25519).
fn identity_of(seeds: &[[u8; 32]; 3]) -> Result<IdentityKeys, Box<dyn std::error::Error>> {
    let [ed, mldsa, x] = seeds;
    Ok(IdentityKeys::from_parts(
        HybridSigningKey::from_seeds(ed, mldsa)?,
        IkDhSecret::from_bytes(x)?,
    )?)
}

/// The BK-01 profile with the canaries in `store`; returns the needles of the scan.
fn populate(store: &mut Store) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let identity = SEEDS.iter().fold(vec![1_u8], |mut v, s| {
        v.extend_from_slice(s);
        v
    });
    let own = identity_of(&SEEDS)?;
    let own_fp = own.fingerprint()?;
    let peer = identity_of(&[[1; 32], [2; 32], [3; 32]])?;
    let peer_iks = peer.public().encode()?;
    let peer_fp = fingerprint_of(peer.public())?;
    let profile = Profile::new("Bob", None)?.encode()?;
    let record = [&LINK_KEY[..], &[0x5d; 40]].concat();
    store.txn(|tx| {
        put_identity(tx, 1, &identity, &own_fp, 1)?;
        let contact = Contact {
            id: 1,
            iks: &peer_iks,
            fingerprint: &peer_fp,
            display_name: Some(NAME),
            verified: true,
            routes: None,
            queues: None,
            state: STATE_ACTIVE,
            profile: Some(&profile),
        };
        put_contact(tx, &contact)?;
        put_fixed(tx, 1, &[0xa1; 600])?;
        insert_skipped(tx, 1, 0, &[0xa2; 68])?;
        put_inbox(tx, 1, &[0xa3; 120])?;
        update_trust(tx, 1, Some(TRUST_VERIFIED), None)?;
        insert_prekey(tx, 1, 1, &[0xb1; 96], Some(9))?;
        insert_prekey(tx, 2, 7, &[0xb2; 64], None)?;
        put_relay(tx, 1, b"relay ref", Some(&[0xd1; 32]))?;
        insert_invitation(tx, &[5; 16], &record, 9)
    })?;
    let unsent = OutboxRow {
        msg_id: [6; 16],
        seq: 0,
        kind: 1,
        expire_after: 0,
        payload: Zeroizing::new(MSG.as_bytes().to_vec()),
        queued_ms: 1,
        first_relayed_ms: None,
        state: state::QUEUED,
        cell_id: None,
    };
    store.outbox_insert(1, &unsent)?;
    store.connection_kat().execute(
        "INSERT INTO settings (key, value) VALUES ('own_name', ?1)",
        [OWN.as_bytes()],
    )?;
    let utf16 = utf16le(MSG);
    for (msg_id, direction, payload) in [
        ([1; 16], Direction::In, MSG.as_bytes()),
        ([2; 16], Direction::Out, utf16.as_slice()),
    ] {
        store.insert_message(&NewMessage {
            contact_id: 1,
            msg_id,
            direction,
            kind: 1,
            ts_ms: 1_000,
            expire_after: 0,
            payload,
        })?;
    }
    let mut needles = vec![
        MSG.as_bytes().to_vec(),
        utf16,
        NAME.as_bytes().to_vec(),
        OWN.as_bytes().to_vec(),
        own_fp.to_vec(),
        peer_fp.to_vec(),
        LINK_KEY.to_vec(),
        PASS.as_bytes().to_vec(),
    ];
    needles.extend(hex(&own_fp));
    needles.extend(hex(&peer_fp));
    needles.extend(SEEDS.iter().map(|s| s.to_vec()));
    for iks in [own.public(), peer.public()] {
        needles.push(iks.ik_ed25519.as_bytes().to_vec());
        needles.push(iks.ik_mldsa65.to_vec());
        needles.push(iks.ik_dh.as_bytes().to_vec());
    }
    Ok(needles)
}

/// FO-03 [O-01] (CS-3.5): the export file of the BK-01 profile holds no canary — the message text (ASCII/UTF-8 and
/// UTF-16LE), the contact's display name, the own name, both fingerprints (raw, lower and upper hex), every
/// `IKSPublic` component (raw), the invitation `link_key`, the identity seeds and the passphrase — as raw bytes, and no
/// printable run of it contains a canary substring of 8 bytes or more.
#[test]
fn export_file_has_no_plaintext() -> R {
    let dir = TempDir::new("fo03")?;
    let mut store = Store::open(&dir.path().join("profile"), &TestKey::db_key())?;
    let needles = populate(&mut store)?;
    let out = dir.path().join("export");
    std::fs::create_dir_all(&out)?;
    export_kat(
        &store,
        &out.join("profile.secmpbackup"),
        PASS.as_bytes(),
        Argon2Params::kat_small(),
    )?;
    drop(store);
    let refs: Vec<&[u8]> = needles.iter().map(Vec::as_slice).collect();
    let (hits, files, bytes) = scan_dir(&out, &refs, 8)?;
    assert_eq!(files, 1, "the export file alone");
    assert!(bytes > 0);
    assert_eq!(hits, vec![], "canaries in the export file");
    Ok(())
}

/// The test the FO-01a child runs again.
const TEST_FO01A: &str = "m7_forensic::store_dir_has_no_plaintext";
/// The role of the FO-01a child.
const ROLE_FO01A: &str = "fo01a";
/// The environment variable that carries the directory of the child's result.
const OUT_FO01A: &str = "SECMP_FO01A_OUT";
/// The environment the child runs in (FO-02): variable and name of its empty directory.
const ENV_DIRS: [(&str, &str); 9] = [
    ("HOME", "home"),
    ("TMPDIR", "tmp"),
    ("TMP", "tmp"),
    ("TEMP", "tmp"),
    ("XDG_DATA_HOME", "xdg-data"),
    ("XDG_CONFIG_HOME", "xdg-config"),
    ("XDG_CACHE_HOME", "xdg-cache"),
    ("XDG_STATE_HOME", "xdg-state"),
    ("XDG_RUNTIME_DIR", "xdg-runtime"),
];
/// The rounds of the chat (two messages each).
const ROUNDS: u64 = 25;

/// The canaries of the scan with their labels; the failure messages carry the labels only.
struct Needles {
    labels: Vec<String>,
    bytes: Vec<Zeroizing<Vec<u8>>>,
}

impl Needles {
    const fn new() -> Self {
        Self {
            labels: Vec::new(),
            bytes: Vec::new(),
        }
    }

    /// A needle `bytes` named `label` (an empty one is skipped).
    fn add(&mut self, label: &str, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.labels.push(label.to_owned());
            self.bytes.push(Zeroizing::new(bytes.to_vec()));
        }
    }

    /// The needle `bytes` and its UTF-16LE form.
    fn add_text(&mut self, label: &str, text: &str) {
        self.add(label, text.as_bytes());
        self.add(&format!("{label} utf16"), &utf16le(text));
    }

    fn refs(&self) -> Vec<&[u8]> {
        self.bytes.iter().map(|b| b.as_slice()).collect()
    }
}

/// A cursor over an encoded state.
struct Cur<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let part = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(part)
    }

    /// `opt(x)`: `0x00`, or `0x01 ‖ x` of `n` bytes.
    fn opt(&mut self, n: usize) -> Option<Field<'a>> {
        match *self.take(1)?.first()? {
            0 => Some(Field::Absent),
            1 => Some(Field::Present(self.take(n)?)),
            _ => None,
        }
    }
}

/// An optional field of an encoded state.
enum Field<'a> {
    Absent,
    Present(&'a [u8]),
}

/// The named secrets of a state.
type Keys = Vec<(&'static str, Zeroizing<Vec<u8>>)>;

/// The secrets of a `RatchetStateV1` fixed part (`secmp-proto/src/tr/state.rs`): `rk`, `dh_s.sk`, `kem_s.seed` and the
/// chain and header keys that are present, by name; `None` unless the parse ends 12 bytes (`n_s`, `n_r`, `pn`) before the end.
fn state_keys(fixed: &[u8]) -> Option<Keys> {
    let mut c = Cur {
        bytes: fixed,
        at: 0,
    };
    let keep = |b: &[u8]| Zeroizing::new(b.to_vec());
    c.take(33)?; // fmt, sb
    let mut out = vec![("rk", keep(c.take(32)?)), ("dh_s", keep(c.take(32)?))];
    c.opt(32)?; // dh_r
    out.push(("kem_s", keep(c.take(64)?)));
    c.opt(1184)?; // kem_r
    c.opt(1088)?; // last_ct_r
    c.opt(1088)?; // ct_s
    for name in ["ck_s", "ck_r", "hk_s", "hk_r", "nhk_s", "nhk_r"] {
        if let Field::Present(key) = c.opt(32)? {
            out.push((name, keep(key)));
        }
    }
    (c.at.checked_add(12)? == fixed.len()).then_some(out)
}

/// The rows of the session of contact 1 of client `i`.
fn rows_of(d: &mut VirtualDriver, i: usize) -> SessionRows {
    let store = hub(d, i).profile_store();
    let guard = store.lock().unwrap();
    guard.session_rows(1).unwrap().expect("the session rows")
}

/// The ASCII text a `SafetyNumber` of client `i` shows.
fn safety_number(d: &mut VirtualDriver, i: usize) -> String {
    let shown = hub(d, i)
        .core_mut()
        .handle(Request::SafetyNumber {
            contact: ContactId(1),
        })
        .unwrap();
    match shown {
        Response::SafetyNumber(s) => s,
        _ => unreachable!("a SafetyNumber is answered with SafetyNumber"),
    }
}

/// Both sides verify the safety number; its 60 digits are a needle.
fn verify_pair(d: &mut VirtualDriver, nd: &mut Needles, sides: [&Party; 2]) {
    let [host, guest] = sides;
    let digits = |s: String| s.chars().filter(char::is_ascii_digit).collect::<String>();
    let (one, two) = (
        digits(safety_number(d, host.idx)),
        digits(safety_number(d, guest.idx)),
    );
    assert!(one == two && one.len() == 60, "the safety numbers differ");
    for p in sides {
        let answer = hub(d, p.idx)
            .core_mut()
            .handle(Request::Verify {
                contact: ContactId(1),
                digits: one.clone(),
            })
            .unwrap();
        assert!(matches!(answer, Response::Verified(true)), "verified");
    }
    nd.add("safety number digits", one.as_bytes());
}

/// `KDF_CK` of the sending and receiving chain keys of client `i` now: the message keys of the next cells (HB-45).
fn add_chain_mks(d: &mut VirtualDriver, nd: &mut Needles, i: usize, tag: &str) {
    let rows = rows_of(d, i);
    let keys = state_keys(&rows.fixed).expect("the fixed part parses");
    for (dir, name) in [("send", "ck_s"), ("recv", "ck_r")] {
        if let Some((_, ck)) = keys.iter().find(|(n, _)| *n == name) {
            let ck = SecretBytes::<32>::from_slice(ck).unwrap();
            let (_next, mk) = kdf_ck(&ck).unwrap();
            nd.add(&format!("mk {dir} {tag}"), mk.expose_secret());
        }
    }
}

/// The number of messages from contact 1 client `i` was told of since the last call.
fn count_received(d: &mut VirtualDriver, i: usize) -> usize {
    hub(d, i)
        .core_mut()
        .take_events()
        .iter()
        .filter(
            |e| matches!(&e.event, Event::MessageReceived { contact, .. } if *contact == ContactId(1)),
        )
        .count()
}

/// Add what each side was told of since the last call to `counts`.
fn tally(d: &mut VirtualDriver, sides: [&Party; 2], counts: &mut [usize; 2]) {
    for (n, p) in sides.iter().enumerate() {
        let c = counts.get_mut(n).unwrap();
        *c = c.saturating_add(count_received(d, p.idx));
    }
}

/// 25 rounds: the host sends message `2 r`, the guest `2 r + 1`, each carrying a canary text; the chain keys are read before
/// every round.
fn chat(d: &mut VirtualDriver, nd: &mut Needles, sides: [&Party; 2]) {
    let [host, guest] = sides;
    let mut counts = [0_usize; 2];
    for r in 0..ROUNDS {
        for (side, p) in [("host", host), ("guest", guest)] {
            add_chain_mks(d, nd, p.idx, &format!("{side} {r}"));
        }
        for (odd, p) in [(0_u64, host), (1_u64, guest)] {
            let m = r.saturating_mul(2).saturating_add(odd);
            let text = format!("CANARY-MSG-{:016x}", 0xf0a1_0000_0000_0000_u64 | m);
            nd.add_text(&format!("text {m}"), &text);
            // a text payload holds no U+0000 (ADR-054): UTF-16LE of ASCII cannot be sent, its form is a needle of every text
            let sent = hub(d, p.idx).core_mut().handle(Request::Send {
                contact: ContactId(1),
                kind: 1,
                payload: Zeroizing::new(text.into_bytes()),
                expire_after: 0,
            });
            assert!(matches!(sent, Ok(Response::Sent(_))), "message {m} queued");
        }
        let t = d.now();
        d.run_until(t.saturating_add(10_000));
        tally(d, sides, &mut counts);
    }
    // each side's receipts share its slots with its messages: the last ones need time (at most three more hours)
    let t = d.now();
    d.run_until(t.saturating_add(150_000));
    tally(d, sides, &mut counts);
    let end = d.now().saturating_add(10_800_000);
    while counts.iter().any(|c| *c < 25) && d.now() < end {
        let t = d.now();
        d.run_until(t.saturating_add(60_000));
        tally(d, sides, &mut counts);
    }
    assert!(
        counts.iter().all(|c| *c == 25),
        "each side received 25, counts {counts:?}"
    );
}

/// The secrets of the store of `p` (the peer is called `peer`): fingerprint, identity, store keys, ratchet state.
fn store_secrets(d: &mut VirtualDriver, nd: &mut Needles, p: &Party, peer: &str) {
    let side = p.idx;
    let answer = hub(d, p.idx).core_mut().handle(Request::Contacts).unwrap();
    let Response::Contacts(list) = answer else {
        unreachable!("Contacts is answered with Contacts")
    };
    let contact = list.first().unwrap();
    assert!(
        contact.display_name.as_deref() == Some(peer),
        "the canary name is stored"
    );
    nd.add(&format!("fingerprint raw {side}"), &contact.fingerprint);
    for (form, h) in ["lower", "upper"].iter().zip(hex(&contact.fingerprint)) {
        nd.add(&format!("fingerprint {form} {side}"), &h);
    }
    let section = {
        let store = hub(d, p.idx).profile_store();
        let guard = store.lock().unwrap();
        guard.identity_secret(1).unwrap().expect("the identity")
    };
    assert_eq!(section.len(), 97);
    for (n, range) in [(0, 1..33), (1, 33..65), (2, 65..97)] {
        nd.add(
            &format!("identity seed {n} {side}"),
            section.get(range).unwrap(),
        );
    }
    let keys = IdentityKeys::from_section(&section).unwrap();
    let iks = keys.public();
    nd.add(&format!("IKS ed25519 {side}"), iks.ik_ed25519.as_bytes());
    nd.add(&format!("IKS ml-dsa {side}"), &iks.ik_mldsa65.to_vec());
    nd.add(&format!("IKS dh {side}"), iks.ik_dh.as_bytes());
    let unlocked = unlock_kat(&p.dir, PROFILE_PASS, Argon2Params::kat_small()).unwrap();
    nd.add(&format!("MK {side}"), unlocked.mk_kat().expose_secret());
    nd.add(
        &format!("K_db {side}"),
        unlocked.db_kat().unwrap().locked().expose_secret(),
    );
    for (n, table) in Table::ALL.into_iter().enumerate() {
        let key = unlocked.table_key_kat(table).unwrap();
        nd.add(
            &format!("table key {n} {side}"),
            key.locked().expose_secret(),
        );
    }
    drop(unlocked);
    let wrap = std::fs::read(p.dir.join(WRAP_FILE)).unwrap();
    let salt = <[u8; 16]>::try_from(wrap.get(1..17).unwrap()).unwrap();
    let kek = kek_kat(PROFILE_PASS, &salt, Argon2Params::kat_small()).unwrap();
    nd.add(&format!("KEK {side}"), kek.locked().expose_secret());
    let rows = rows_of(d, p.idx);
    for (name, key) in state_keys(&rows.fixed).expect("the fixed part parses") {
        nd.add(&format!("state {name} {side}"), &key);
    }
    for (ord, entry) in &rows.skipped {
        assert_eq!(entry.len(), 68, "a skipped entry");
        nd.add(
            &format!("skipped hk {ord} {side}"),
            entry.get(..32).unwrap(),
        );
        nd.add(
            &format!("skipped mk {ord} {side}"),
            entry.get(36..68).unwrap(),
        );
    }
}

/// `src` copied to `dst` without the `lock` file (empty; Windows holds it mandatory-locked while the store is open).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let (from, to) = (entry.path(), dst.join(entry.file_name()));
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else if entry.file_name() == "lock" {
            assert_eq!(std::fs::metadata(&from)?.len(), 0, "the lock file is empty");
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Scan `dir` for every needle; no hit, and something was scanned. Returns `(files, bytes)`.
fn scan_clean(dir: &Path, nd: &Needles, what: &str) -> (u64, u64) {
    let (hits, files, bytes) = scan_dir(dir, &nd.refs(), 8).unwrap();
    let found: Vec<String> = hits
        .iter()
        .map(|h| {
            let label = nd.labels.get(h.needle).map_or("?", String::as_str);
            format!("({label}, {}, raw {})", h.file.display(), h.raw)
        })
        .collect();
    assert!(found.is_empty(), "{what}: forensic hits {found:?}");
    assert!(files > 0 && bytes > 0, "{what}: nothing was scanned");
    (files, bytes)
}

/// The scan of the state an `abort` leaves (Q292): a copy of every file of the profile directory of `p` at an idle point,
/// the WAL not checkpointed. Returns `(files, bytes, wal bytes)`.
fn scan_abort(p: &Party, nd: &Needles, out: &Path) -> (u64, u64, u64) {
    let copy = out.join(format!("abort-{}", p.idx));
    copy_tree(&p.dir, &copy).unwrap();
    let wal = std::fs::metadata(copy.join("profile.db-wal"))
        .unwrap()
        .len();
    assert!(wal > 0, "the WAL was not checkpointed");
    let (files, bytes) = scan_clean(&copy, nd, "abort image");
    (files, bytes, wal)
}

/// FO-02: the Tor directories are the profile's, and deleting the profile directory leaves nothing of it.
fn tor_and_delete(p: &Party) {
    let config = secmp_transport::tor::config(&p.dir).unwrap();
    let debug = format!("{config:?}");
    for sub in ["state", "cache"] {
        let path = format!("{:?}", p.dir.join("tor").join(sub).to_string_lossy());
        assert!(
            debug.contains(path.trim_matches('"')),
            "tor {sub} is in the profile"
        );
    }
    assert!(!debug.contains("${ARTI"), "no Arti default path");
    std::fs::remove_dir_all(&p.dir).unwrap();
    assert!(!p.dir.exists() && !p.dir.join("tor").exists());
}

/// The FO-01a run in the child: the scenario, the needles, the two scans, FO-02's directory part; writes `out/result.txt`.
fn fo01a_child(out: &Path) -> R {
    measure_writes(true);
    let mut d = driver();
    let host = add_party_mode(&mut d, NAME, 3, (Mode::Balanced, 11));
    let guest = add_party_mode(&mut d, OWN, 3, (Mode::Balanced, 12));
    let inv = invite_pair(&mut d, &host, &guest);
    d.run_until(600_000);
    for p in [&host, &guest] {
        assert_eq!(d.client_ref(p.idx).hub_errors, Vec::<String>::new());
        assert_eq!(contact_ids(&mut d, p.idx), vec![1]);
    }
    let mut nd = Needles::new();
    nd.add("link_key", &inv.link_key);
    nd.add("invitation uri", inv.uri.as_bytes());
    nd.add("passphrase", PROFILE_PASS);
    nd.add_text("host name", NAME);
    nd.add_text("guest name", OWN);
    verify_pair(&mut d, &mut nd, [&host, &guest]);
    chat(&mut d, &mut nd, [&host, &guest]);
    store_secrets(&mut d, &mut nd, &host, OWN);
    store_secrets(&mut d, &mut nd, &guest, NAME);
    let mut report = format!("needles {}\n", nd.bytes.len());
    for p in [&host, &guest] {
        let (files, bytes, wal) = scan_abort(p, &nd, out);
        let _ = writeln!(
            report,
            "abort image {}: {files} files, {bytes} bytes, WAL {wal} bytes",
            p.idx
        );
    }
    for p in [&host, &guest] {
        d.client(p.idx).hub = None;
    }
    for p in [&host, &guest] {
        let (files, bytes) = scan_clean(&p.dir, &nd, "clean close");
        let _ = writeln!(
            report,
            "clean close {}: {files} files, {bytes} bytes",
            p.idx
        );
    }
    for p in [&host, &guest] {
        tor_and_delete(p);
    }
    std::fs::write(out.join("result.txt"), report)?;
    Ok(())
}

/// FO-01a [O-01] (CS-3.5, with FO-02): two profiles that chatted hold none of the canaries — names (ASCII, UTF-16LE),
/// fingerprints, identity seeds and keys, store keys, the ratchet's keys and the message keys of the last slots, the
/// invitation, the safety number, the passphrase, the message texts — in the image an `abort` leaves nor after a clean
/// close; the run's `HOME`, `TMPDIR`, `TMP`, `TEMP` and `XDG_*` directories stay empty (FO-02).
#[test]
fn store_dir_has_no_plaintext() -> R {
    if child_role().as_deref() == Some(ROLE_FO01A) {
        let out = std::env::var_os(OUT_FO01A).map(PathBuf::from);
        return fo01a_child(&out.ok_or("no result directory")?);
    }
    let root = TempDir::new("fo01a")?;
    let out = root.path().join("out");
    std::fs::create_dir_all(&out)?;
    let mut env: Vec<(&str, PathBuf)> = vec![(OUT_FO01A, out.clone())];
    for (var, name) in ENV_DIRS {
        let dir = root.path().join(name);
        std::fs::create_dir_all(&dir)?;
        env.push((var, dir));
    }
    let refs: Vec<(&str, &Path)> = env.iter().map(|(k, v)| (*k, v.as_path())).collect();
    assert!(
        run_child(TEST_FO01A, ROLE_FO01A, &refs)?,
        "the FO-01a child failed"
    );
    for (_, name) in ENV_DIRS {
        let left: Vec<String> = std::fs::read_dir(root.path().join(name))?
            .map(|e| {
                e.map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .replace(NAME, "<name>")
                        .replace(OWN, "<own>")
                })
            })
            .collect::<Result<_, _>>()?;
        assert!(left.is_empty(), "FO-02: {name} is not empty: {left:?}");
    }
    let result = std::fs::read_to_string(out.join("result.txt"))?;
    super::m6_common::evidence("FO-01a", &result);
    Ok(())
}
