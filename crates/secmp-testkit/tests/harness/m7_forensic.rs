// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 FO-03 (CS-3.5 `docs/04:56`): the forensic scan of a backup export file. The source profile holds the
//! input of BK-01 (`secmp-store` `backup::tests::contents_whitelist`: the identity, a contact, settings, a received and
//! a sent message, a session, prekeys, the outbox, a relay and an invitation) with the canaries of the Conventions
//! (TEST-SPEC-M7 `:55-57`) placed in it; the export file (`kat_small`) is scanned with the FO-01a scan
//! (`secmp_store::kat::scan_dir`: raw bytes, and substrings ≥ 8 B inside printable runs ≥ 4 B).

use std::fmt::Write as _;

use secmp_crypto::{HybridSigningKey, Zeroizing};
use secmp_proto::Encode;
use secmp_proto::prekeys::{IdentityKeys, IkDhSecret, fingerprint_of};
use secmp_proto::wire::inv::Profile;
use secmp_store::Store;
use secmp_store::backup::export_kat;
use secmp_store::contacts::{Contact, STATE_ACTIVE, put_contact};
use secmp_store::kat::{TempDir, TestKey, scan_dir};
use secmp_store::messages::{Direction, NewMessage};
use secmp_store::outbox::{OutboxRow, state};
use secmp_store::profile::{insert_invitation, insert_prekey, put_identity, put_relay};
use secmp_store::sessions::{insert_skipped, put_fixed, put_inbox, put_trust};
use secmp_store::wrap::Argon2Params;

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
        put_trust(tx, 1, &[1])?;
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
