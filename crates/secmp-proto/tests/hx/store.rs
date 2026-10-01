// SPDX-License-Identifier: AGPL-3.0-or-later
//! The prekey store and the invitation records (TEST-SPEC-M4 N-25, N-61 … N-65, N-72; spec §5.2, §6.1, §6.3,
//! ADR-044 (d)).

use secmp_proto::inv::{IssueError, MAX_INVITATION_LIFE_S};
use secmp_proto::prekeys::{
    IdentityKeys, IssueParams, Issued, MemoryPrekeyStore, PrekeyStore, SPK_ROTATION_S,
};
use secmp_proto::tr::OsEntropy;
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
