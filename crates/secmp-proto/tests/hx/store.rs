// SPDX-License-Identifier: AGPL-3.0-or-later
//! The prekey store and the invitation records (TEST-SPEC-M4 N-25, N-61 … N-65, N-72; spec §5.2, §6.1, §6.3,
//! ADR-044 (d)).

use secmp_crypto::SecretBytes;
use secmp_proto::inv::{IssueError, MAX_INVITATION_LIFE_S};
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, Issued, MemoryPrekeyStore, PrekeyStore,
    SPK_ROTATION_S, SpkGeneration,
};
use secmp_proto::tr::{FixedEntropy, OsEntropy};
use secmp_proto::wire::Period;
use secmp_proto::wire::inv::{LinkDataV1, Profile};

use crate::fixture::relay_ref;
use crate::hx_gen::harness::{CREATED, EXPIRES};

fn params(now: u64, expires: u64, spk_expiry: u64) -> IssueParams {
    IssueParams {
        relay: relay_ref(10),
        inv_period: Period::S20,
        profile: Profile::new("bob", None).unwrap(),
        now,
        expires,
        spk_expiry,
    }
}

fn identity() -> IdentityKeys {
    IdentityKeys::generate(&mut OsEntropy).unwrap()
}

fn opened(issued: &Issued) -> LinkDataV1 {
    use secmp_proto::Encode;
    secmp_proto::inv::open_blob(
        &issued.invitation.ld_id,
        &issued.invitation.link_key,
        &issued.blob.encode().unwrap(),
    )
    .unwrap()
}

#[test]
fn inviter_create_enforces_own_bounds() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let max = CREATED + MAX_INVITATION_LIFE_S;
    // control: exactly 30 days and spk_expiry = expires
    store
        .issue_invitation(&id, params(CREATED, max, max), &mut OsEntropy)
        .unwrap();
    let before = store.digest_kat();
    let spk_ids = store.spk_ids();
    for (what, p, expected) in [
        (
            "expires beyond 30 days",
            params(CREATED, max + 1, max + 1),
            IssueError::ExpiresTooLate,
        ),
        (
            "spk_expiry before expires",
            params(CREATED, max, max - 1),
            IssueError::SpkExpiryBeforeExpires,
        ),
        (
            "already expired",
            params(CREATED, CREATED, max),
            IssueError::AlreadyExpired,
        ),
    ] {
        let err = store.issue_invitation(&id, p, &mut OsEntropy).err();
        assert_eq!(
            err,
            Some(expected),
            "{what}: a local error, not the wire's Rejected"
        );
        assert_eq!(
            store.digest_kat(),
            before,
            "{what}: nothing issued, nothing recorded"
        );
        assert_eq!(store.spk_ids(), spk_ids);
    }
}

#[test]
fn prekey_store_opk_consume_twice_fails() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let issued = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let opk_id = opened(&issued).bundle.opk_id;
    store.delete_opk(opk_id).unwrap();
    let after_first = store.digest_kat();
    assert_eq!(
        store.delete_opk(opk_id).err(),
        Some(secmp_proto::Error::Rejected)
    );
    assert_eq!(
        store.digest_kat(),
        after_first,
        "the second consume has no side effect"
    );
    assert!(store.opk(opk_id).is_none());
}

#[test]
fn prekey_store_spk_rotates_weekly() {
    let mut store = MemoryPrekeyStore::default();
    let mut e = OsEntropy;
    let first = store.rotate_if_due(CREATED, &mut e).unwrap();
    let rpk_first = store.current_spk().unwrap().rpk_public().unwrap();
    assert_eq!(
        store
            .rotate_if_due(CREATED + SPK_ROTATION_S - 1, &mut e)
            .unwrap(),
        first,
        "not due before 7 days"
    );
    let second = store
        .rotate_if_due(CREATED + SPK_ROTATION_S, &mut e)
        .unwrap();
    assert_eq!(second, first + 1, "a new generation at 7 days");
    let current = store.current_spk().unwrap();
    assert_eq!(current.id(), second);
    assert_ne!(
        current.rpk_public().unwrap().as_bytes(),
        rpk_first.as_bytes(),
        "the new generation brings its own RPK"
    );
    assert_eq!(
        store
            .rotate_if_due(CREATED + SPK_ROTATION_S + 1, &mut e)
            .unwrap(),
        second
    );
}

#[test]
fn prekey_store_retains_spk_while_referenced() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let issued = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let old_spk = opened(&issued).bundle.spk_id;
    // rotation while the unexpired invitation references the old SPK
    let eight_days = CREATED + 8 * 24 * 3600;
    let new_spk = store.rotate_if_due(eight_days, &mut OsEntropy).unwrap();
    assert_ne!(new_spk, old_spk);
    assert!(store.retire_expired(eight_days).is_empty());
    assert!(
        store.spk(old_spk).is_some(),
        "retained while an unexpired invitation references it"
    );
    assert!(store.spk(new_spk).is_some());
    // retained until that invitation expires, then deleted with its RPK (zeroized on drop)
    assert!(store.retire_expired(EXPIRES - 1).is_empty());
    assert!(
        store.spk(old_spk).is_some(),
        "still retained one second before expiry"
    );
    let retired = store.retire_expired(EXPIRES);
    assert_eq!(retired, vec![issued.invitation.ld_id]);
    assert!(
        store.spk(old_spk).is_none(),
        "deleted when the last referencing invitation expired"
    );
    assert!(store.spk(new_spk).is_some(), "the current generation stays");
}

#[test]
fn prekey_store_rpk_follows_its_spk() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let issued = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let first = opened(&issued).bundle;
    let later = CREATED + 8 * 24 * 3600;
    let second_issued = store
        .issue_invitation(&id, params(later, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let second = opened(&second_issued).bundle;
    // each bundle's RPK is its generation's, and the generations have different RPKs
    assert_ne!(first.spk_id, second.spk_id);
    assert_ne!(first.rpk_kem.as_bytes(), second.rpk_kem.as_bytes());
    assert_eq!(
        store
            .spk(first.spk_id)
            .unwrap()
            .rpk_public()
            .unwrap()
            .as_bytes(),
        first.rpk_kem.as_bytes()
    );
    assert_eq!(
        store
            .spk(second.spk_id)
            .unwrap()
            .rpk_public()
            .unwrap()
            .as_bytes(),
        second.rpk_kem.as_bytes()
    );
    // the RPK's lifetime is its SPK's: when the SPK goes, nothing of it is reachable
    store.retire_expired(EXPIRES);
    assert!(store.spk(first.spk_id).is_none());
}

#[test]
fn prekey_store_one_opk_per_invitation() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let a = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let b = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    let (ba, bb) = (opened(&a).bundle, opened(&b).bundle);
    assert_ne!(ba.opk_id, bb.opk_id, "distinct OPKs");
    assert_ne!(ba.opk_dh.as_bytes(), bb.opk_dh.as_bytes());
    assert_ne!(ba.opk_kem.as_bytes(), bb.opk_kem.as_bytes());
    assert_eq!(
        store.record(&a.invitation.ld_id).unwrap().opk_id,
        ba.opk_id,
        "each record names its own opk_id"
    );
    assert_eq!(store.record(&b.invitation.ld_id).unwrap().opk_id, bb.opk_id);
    assert_eq!(store.opk_ids().len(), 2);
}

#[test]
fn expired_invitation_record_is_not_offered_to_accept() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    let short = CREATED + 1000;
    let a = store
        .issue_invitation(&id, params(CREATED, short, short), &mut OsEntropy)
        .unwrap();
    let b = store
        .issue_invitation(&id, params(CREATED, EXPIRES, EXPIRES), &mut OsEntropy)
        .unwrap();
    // `accept` has no clock; the record lifecycle decides what is offered
    let offered = |now: u64, s: &MemoryPrekeyStore| {
        s.offered_records(now)
            .iter()
            .map(|r| r.ld_id)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        offered(short - 1, &store),
        vec![a.invitation.ld_id, b.invitation.ld_id]
    );
    assert_eq!(
        offered(short, &store),
        vec![b.invitation.ld_id],
        "expires = now is expired"
    );
    assert_eq!(offered(EXPIRES, &store), Vec::<[u8; 16]>::new());
    // its queue is retired: the ld_id comes back from retire_expired, and the record and its OPK are gone
    let opk_a = store.record(&a.invitation.ld_id).unwrap().opk_id;
    let retired = store.retire_expired(short);
    assert_eq!(retired, vec![a.invitation.ld_id]);
    assert!(store.record(&a.invitation.ld_id).is_none());
    assert!(store.opk(opk_a).is_none());
    assert!(store.record(&b.invitation.ld_id).is_some());
}

// ---- M4-12: the HX mutants of R-60 ----

/// A store with SPK generation 1 and OPKs 1 and 2 (ids from `starting_at(1, 1)`), no records.
fn plain_store() -> MemoryPrekeyStore {
    let mut store = MemoryPrekeyStore::default();
    store.create_spk(CREATED, &mut OsEntropy).unwrap();
    store.issue_opk(&mut OsEntropy).unwrap();
    store.issue_opk(&mut OsEntropy).unwrap();
    store
}

fn record(ld: u8, spk_id: u32, opk_id: u32) -> InvitationRecord {
    InvitationRecord {
        ld_id: [ld; 16],
        link_key: SecretBytes::from_slice(&[0x5a; 32]).unwrap(),
        spk_id,
        opk_id,
        expires: EXPIRES,
    }
}

#[test]
fn spk_rotation_is_seven_days() {
    assert_eq!(SPK_ROTATION_S, 604_800);
}

#[test]
fn spk_generation_created_is_the_issue_time() {
    let mut store = MemoryPrekeyStore::default();
    store.create_spk(CREATED, &mut OsEntropy).unwrap();
    assert_eq!(store.current_spk().unwrap().created(), CREATED);
    let later = CREATED + SPK_ROTATION_S + 5;
    store.rotate_if_due(later, &mut OsEntropy).unwrap();
    assert_eq!(store.current_spk().unwrap().created(), later);
    let direct = SpkGeneration::generate(9, 123_456_789, &mut OsEntropy).unwrap();
    assert_eq!(direct.created(), 123_456_789);
    // the store exposes no retention path that reads `created`: `retire_expired` keeps a generation by the current
    // generation and by record references only (§6.1), so the accessor is checked on its own
}

fn assert_add_rejected(store: &mut MemoryPrekeyStore, rec: InvitationRecord) {
    let before = store.digest_kat();
    assert_eq!(
        store.add_record(rec).err(),
        Some(secmp_proto::Error::Rejected)
    );
    assert_eq!(store.digest_kat(), before, "a rejected add changes nothing");
}

#[test]
fn add_record_rejects_unknown_spk_alone() {
    let mut store = plain_store();
    assert_add_rejected(&mut store, record(1, 99, 1));
    store.add_record(record(1, 1, 1)).unwrap();
}

#[test]
fn add_record_rejects_unknown_opk_alone() {
    let mut store = plain_store();
    assert_add_rejected(&mut store, record(1, 1, 99));
    store.add_record(record(1, 1, 1)).unwrap();
}

#[test]
fn add_record_rejects_duplicate_ld_id_alone() {
    let mut store = plain_store();
    store.add_record(record(1, 1, 1)).unwrap();
    assert_add_rejected(&mut store, record(1, 1, 2));
    store.add_record(record(2, 1, 2)).unwrap();
}

/// M4 review C-11 (R-25): one record per OPK (§6.1 single use) — a second record naming a recorded OPK is refused
/// alone (new `ld_id`, held SPK, the OPK held but already recorded), the store unchanged; the same record with another
/// held OPK is accepted.
#[test]
fn add_record_rejects_duplicate_opk_id_alone() {
    let mut store = plain_store();
    store.add_record(record(1, 1, 1)).unwrap();
    assert_add_rejected(&mut store, record(2, 1, 1));
    store.add_record(record(2, 1, 2)).unwrap();
}

/// A deterministic entropy stream long enough for one `issue_invitation` after the SPK exists.
fn stream() -> Vec<u8> {
    (0..16_384_u32)
        .map(|i| u8::try_from(i.wrapping_mul(31).wrapping_add(7) % 251).unwrap())
        .collect()
}

#[test]
fn issue_invitation_failure_removes_only_that_opk() {
    let id = identity();
    let mut store = MemoryPrekeyStore::default();
    store.create_spk(CREATED, &mut OsEntropy).unwrap();
    // the first issuance consumes a prefix of the stream and records `ld_id` L with OPK 1
    let first = store
        .issue_invitation(
            &id,
            params(CREATED, EXPIRES, EXPIRES),
            &mut FixedEntropy::new(&stream()),
        )
        .unwrap();
    assert_eq!(store.opk_ids(), vec![1]);
    // the same stream again: OPK 2 is taken, then `ld_id` = L collides with the recorded one
    let err = store
        .issue_invitation(
            &id,
            params(CREATED, EXPIRES, EXPIRES),
            &mut FixedEntropy::new(&stream()),
        )
        .err();
    assert!(err.is_some(), "a duplicate ld_id fails the issuance");
    assert_eq!(
        store.opk_ids(),
        vec![1],
        "the failed issuance's OPK 2 is gone, the earlier invitation's OPK 1 stays"
    );
    assert!(store.record(&first.invitation.ld_id).is_some());
}

fn store_with_record_naming(named: u32) -> MemoryPrekeyStore {
    let mut store = plain_store();
    store.add_record(record(1, 1, named)).unwrap();
    store
}

#[test]
fn commit_accept_rejects_missing_opk_alone() {
    let mut store = store_with_record_naming(1);
    store.delete_opk(1).unwrap();
    let before = store.digest_kat();
    assert_eq!(
        store.commit_accept(1, &[1; 16]).err(),
        Some(secmp_proto::Error::Rejected)
    );
    assert_eq!(store.digest_kat(), before, "the record is not consumed");
    assert!(store.record(&[1; 16]).is_some());
}

#[test]
fn commit_accept_rejects_missing_record_alone() {
    let mut store = store_with_record_naming(1);
    let before = store.digest_kat();
    assert_eq!(
        store.commit_accept(1, &[7; 16]).err(),
        Some(secmp_proto::Error::Rejected)
    );
    assert_eq!(store.digest_kat(), before);
    assert!(store.opk(1).is_some());
}

#[test]
fn commit_accept_rejects_mismatched_opk() {
    // R-64: the record of `ld_id` names OPK 1; the call names OPK 2, which is held too
    let mut store = store_with_record_naming(1);
    let before = store.digest_kat();
    assert_eq!(
        store.commit_accept(2, &[1; 16]).err(),
        Some(secmp_proto::Error::Rejected)
    );
    assert_eq!(store.digest_kat(), before, "nothing changed");
    assert!(store.opk(1).is_some() && store.opk(2).is_some());
    assert!(store.record(&[1; 16]).is_some());
    // and the matching call commits both
    store.commit_accept(1, &[1; 16]).unwrap();
    assert!(store.opk(1).is_none() && store.opk(2).is_some());
    assert!(store.record(&[1; 16]).is_none());
}
