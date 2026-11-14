// SPDX-License-Identifier: AGPL-3.0-or-later
//! The contacts (spec §6.7, §7.6; `docs/02:95`): one row per peer identity, keyed by the **whole** `IKSPublic` — its
//! fingerprint (§6.2) — never by the signing half alone (`docs/03:356`, RT-3). The contact of a handshake is stored unverified; a
//! second handshake presenting an identity that a contact already holds creates a second, unverified contact beside it
//! and raises [`Event::DuplicateIdentity`] — nothing is merged (ADR-044 (f), O-29, OPEN-M7-29 A).
//!
//! **Verification (§6.7).** The safety number is the 60 digits of `SafetyNumber::new(fp_own, fp_peer)`; a contact is
//! verified by the digits the user types or by the QR the peer shows: `"SecMP-SAS/1" ‖ fp_peer ‖ fp_own` as the scanner
//! reads it (the displayer shows its own fingerprint first, Q158). Digits and QR are compared in constant time.
//!
//! **Removal (§7.6 code 1, ADR-054 item 4).** `Control{ContactRemoved}` with no argument marks the contact
//! [`ContactState::Removed`]: real sends are refused ([`Contacts::check_send`]); the scheduler is not told, so the slots
//! keep carrying dummies and the schedule does not change.

use secmp_crypto::{ConstantTimeEq as _, Fingerprint, Label, SafetyNumber};
use secmp_proto::Encode as _;
use secmp_proto::prekeys::fingerprint_of;
use secmp_proto::wire::cell::{ControlBody, ControlCode};
use secmp_proto::wire::inv::{IksPublic, Profile as WireProfile};
use secmp_store::Store;
use secmp_store::contacts::{
    STATE_ACTIVE, STATE_REINVITE_REQUIRED, STATE_REMOVED, StoredContact, set_contact_state,
    set_contact_verified,
};
use secmp_store::sessions::{TRUST_VERIFIED, update_trust};

use crate::api::{Error, Event};
use crate::persist::SharedStore;

pub use crate::api::ContactId;

/// The state of a contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactState {
    /// Sends and receives.
    Active,
    /// Restored from a backup without a session: it must be invited again before anything is sent.
    ReinviteRequired,
    /// The peer sent `Control{ContactRemoved}`: real messages are not sent.
    Removed,
}

impl ContactState {
    fn of(code: i64) -> Result<Self, Error> {
        match code {
            STATE_ACTIVE => Ok(Self::Active),
            STATE_REINVITE_REQUIRED => Ok(Self::ReinviteRequired),
            STATE_REMOVED => Ok(Self::Removed),
            _ => Err(Error::Unavailable),
        }
    }
}

/// A contact as the application sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The id.
    pub id: ContactId,
    /// `fingerprint(IKSPublic)` of the peer's whole identity (§6.2).
    pub fingerprint: [u8; 32],
    /// The user has verified the safety number.
    pub verified: bool,
    /// The name the peer gave itself in its handshake profile (the user's own name for it is set by the application); a
    /// name with a C0, DEL or C1 control character is shown as empty (ADR-054 item 5).
    pub display_name: Option<String>,
    /// The state.
    pub state: ContactState,
}

impl Contact {
    /// The key a list shows next to the name to tell two contacts of one name apart: the whole fingerprint in hex. Two
    /// identities that share `IK_sig` and differ in `IK_dh` have different keys.
    #[must_use]
    pub fn display_key(&self) -> String {
        use core::fmt::Write as _;
        let mut key = String::with_capacity(64);
        for b in self.fingerprint {
            let _ = write!(key, "{b:02x}");
        }
        key
    }
}

/// ADR-054 item 5: a `Profile.name` with a C0 (U+0000–U+001F), DEL (U+007F) or C1 (U+0080–U+009F) control character is
/// shown as empty; the handshake was accepted and the stored name is kept as received.
fn shown_name(name: &str) -> String {
    if name
        .chars()
        .any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
    {
        String::new()
    } else {
        name.to_owned()
    }
}

fn contact_of(c: &StoredContact) -> Result<Contact, Error> {
    Ok(Contact {
        id: ContactId(c.id),
        fingerprint: <[u8; 32]>::try_from(c.fingerprint.as_slice())
            .map_err(|_| Error::Unavailable)?,
        verified: c.verified,
        display_name: c.display_name.as_deref().map(shown_name),
        state: ContactState::of(c.state)?,
    })
}

/// A contact about to be written: the id and the duplicate check were decided under the store lock.
pub(crate) struct Planned {
    /// The id the contact will get.
    pub id: ContactId,
    /// The contact that already holds the identity, if any.
    pub duplicate_of: Option<ContactId>,
    /// `fingerprint(IKSPublic)`.
    pub fingerprint: [u8; 32],
}

/// The contact that holds `fingerprint` (the lowest id), compared in constant time; every contact is compared.
fn holder_of(contacts: &[StoredContact], fingerprint: &[u8; 32]) -> Option<ContactId> {
    let mut found: Option<ContactId> = None;
    for c in contacts {
        if bool::from(c.fingerprint.as_slice().ct_eq(fingerprint.as_slice())) && found.is_none() {
            found = Some(ContactId(c.id));
        }
    }
    found
}

/// Decide the id and the duplicate check of a contact for `peer` (§6.2: the whole identity).
pub(crate) fn plan(store: &Store, peer: &IksPublic) -> Result<Planned, Error> {
    let fingerprint = fingerprint_of(peer)?;
    let existing = store.contacts()?;
    let next = existing
        .iter()
        .map(|c| c.id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::Unavailable)?;
    Ok(Planned {
        id: ContactId(next),
        duplicate_of: holder_of(&existing, &fingerprint),
        fingerprint,
    })
}

/// What the row of a new contact holds beyond its identity.
pub(crate) struct NewContact<'a> {
    pub peer: &'a IksPublic,
    pub profile: &'a WireProfile,
    pub routes: Option<&'a [u8]>,
    pub queues: Option<&'a [u8]>,
}

/// The statements that write `planned` as an unverified, active contact (one statement).
pub(crate) fn write(
    tx: &mut secmp_store::Tx<'_>,
    planned: &Planned,
    c: &NewContact<'_>,
) -> secmp_store::Result<()> {
    let iks = c
        .peer
        .encode()
        .map_err(|_| secmp_store::Error::Unavailable)?;
    let profile = c
        .profile
        .encode()
        .map_err(|_| secmp_store::Error::Unavailable)?;
    secmp_store::contacts::put_contact(
        tx,
        &secmp_store::contacts::Contact {
            id: planned.id.0,
            iks: &iks,
            fingerprint: &planned.fingerprint,
            display_name: Some(c.profile.name()),
            verified: false,
            routes: c.routes,
            queues: c.queues,
            state: STATE_ACTIVE,
            profile: Some(&profile),
        },
    )
}

/// The contacts of a profile (see the module documentation).
pub struct Contacts {
    store: SharedStore,
    own_fp: [u8; 32],
}

impl Contacts {
    /// The contacts in `store`; `own_fp` is the user's fingerprint (the other half of every safety number).
    #[must_use]
    pub const fn new(store: SharedStore, own_fp: [u8; 32]) -> Self {
        Self { store, own_fp }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Store>, Error> {
        self.store.lock().map_err(|_| Error::Unavailable)
    }

    /// Every contact, by id.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn list(&self) -> Result<Vec<Contact>, Error> {
        self.lock()?.contacts()?.iter().map(contact_of).collect()
    }

    /// The contact `id`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or holds no such contact.
    pub fn get(&self, id: ContactId) -> Result<Contact, Error> {
        self.list()?
            .into_iter()
            .find(|c| c.id == id)
            .ok_or(Error::Unavailable)
    }

    /// Add the contact of an accepted handshake: unverified, never merged with a contact that holds the same identity
    /// (which raises [`Event::DuplicateIdentity`] beside the new one). The decision and the write are one store
    /// transaction.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written.
    pub fn add_from_handshake(
        &self,
        peer: &IksPublic,
        profile: &WireProfile,
        routes: Option<&[u8]>,
    ) -> Result<(ContactId, Vec<Event>), Error> {
        let mut store = self.lock()?;
        let planned = plan(&store, peer)?;
        store.txn(|tx| {
            write(
                tx,
                &planned,
                &NewContact {
                    peer,
                    profile,
                    routes,
                    queues: None,
                },
            )
        })?;
        Ok((planned.id, events_of(&planned)))
    }

    /// The safety number of contact `id` (§6.7): 60 digits, the same on both sides.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown.
    pub fn safety_number(&self, id: ContactId) -> Result<SafetyNumber, Error> {
        let peer = Fingerprint::from_bytes(&self.get(id)?.fingerprint)?;
        Ok(SafetyNumber::new(
            &Fingerprint::from_bytes(&self.own_fp)?,
            &peer,
        ))
    }

    /// The QR text this user shows contact `id` to scan (§6.7): `"SecMP-SAS/1" ‖ fp_own ‖ fp_peer`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown.
    pub fn qr_text(&self, id: ContactId) -> Result<Vec<u8>, Error> {
        let c = self.get(id)?;
        Ok([Label::Sas.as_bytes(), &self.own_fp, &c.fingerprint].concat())
    }

    /// Verify contact `id` by the safety-number digits the user typed (spaces and line breaks ignored): `true` and the
    /// contact is verified if they equal the 60 digits, `false` and nothing changes otherwise.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown or the store cannot be written.
    pub(crate) fn confirm_digits(&self, id: ContactId, typed: &str) -> Result<bool, Error> {
        let ok = self.digits_match(id, typed)?;
        self.verified_if(id, ok)
    }

    /// Whether the digits the user typed (spaces and line breaks ignored) equal the safety number of contact `id`, compared
    /// in constant time; nothing is written (the caller verifies the contact with its session, Q205).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown.
    pub fn digits_match(&self, id: ContactId, typed: &str) -> Result<bool, Error> {
        let want = self.safety_number(id)?;
        let typed: Vec<u8> = typed.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        Ok(bool::from(typed.as_slice().ct_eq(want.as_str().as_bytes())))
    }

    /// Verify contact `id` by the QR it showed: `"SecMP-SAS/1" ‖ fp_peer ‖ fp_own`, the displayer's own-first form read by
    /// the scanner (Q158). A QR with the fingerprints swapped, or for another pair, verifies nothing.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown or the store cannot be written.
    ///
    /// No `Request` carries a scanned QR yet (the UI milestone): until then this writer is compiled for the tests only, so
    /// that no unguarded caller exists in the product (C1-4 a).
    #[cfg(test)]
    #[cfg(feature = "kat")]
    pub(crate) fn confirm_qr(&self, id: ContactId, scanned: &[u8]) -> Result<bool, Error> {
        let c = self.get(id)?;
        let want = [Label::Sas.as_bytes(), &c.fingerprint, &self.own_fp].concat();
        let ok = bool::from(scanned.ct_eq(want.as_slice()));
        self.verified_if(id, ok)
    }

    /// Verify contact `id` if `ok`: the contact flag and — when the session has a TRUST row — the trust, in one
    /// transaction under one store lock, so a stored `Frozen` refuses both ([`Error::Frozen`], nothing written; Q205). A
    /// contact without a TRUST row gets the flag only: `update_trust` would create the row and the `init_trust` of the
    /// session's first write would refuse.
    fn verified_if(&self, id: ContactId, ok: bool) -> Result<bool, Error> {
        if !ok {
            return Ok(false);
        }
        let mut store = self.lock()?;
        let has_trust = store.inbox_trust(id.0)?.1.is_some();
        let written = store.txn(|tx| {
            if has_trust {
                update_trust(tx, id.0, Some(TRUST_VERIFIED), None)?;
            }
            set_contact_verified(tx, id.0, true)
        });
        if written.is_err() {
            return Err(crate::sessions::trust_write_refusal(&store, id)?);
        }
        Ok(true)
    }

    /// A `Control` content from contact `id` (§7.6): `ContactRemoved` without an argument marks the contact removed
    /// (ADR-054 item 4); anything else is not this module's. Returns whether the contact was marked.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the contact is unknown or the store cannot be written.
    pub fn on_control(&self, id: ContactId, body: &ControlBody) -> Result<bool, Error> {
        if !matches!(body.code, ControlCode::ContactRemoved) || !body.arg.is_empty() {
            return Ok(false);
        }
        self.lock()?
            .txn(|tx| set_contact_state(tx, id.0, STATE_REMOVED))?;
        Ok(true)
    }

    /// Whether a real message may be queued for contact `id`.
    ///
    /// # Errors
    /// [`Error::Blocked`] for a removed contact, [`Error::ReinviteRequired`] for a restored one,
    /// [`Error::Unavailable`] for an unknown one.
    pub fn check_send(&self, id: ContactId) -> Result<(), Error> {
        match self.get(id)?.state {
            ContactState::Active => Ok(()),
            ContactState::Removed => Err(Error::Blocked),
            ContactState::ReinviteRequired => Err(Error::ReinviteRequired),
        }
    }
}

/// The events of a planned contact.
pub(crate) fn events_of(planned: &Planned) -> Vec<Event> {
    planned
        .duplicate_of
        .map(|existing| Event::DuplicateIdentity {
            existing,
            new: planned.id,
        })
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    /// SE-58 (ADR-054 item 5, EXT2c-5): the shown name is empty exactly when the name holds a C0 (U+0000–U+001F), DEL
    /// (U+007F) or C1 (U+0080–U+009F) character; the neighbours of each range and other Unicode are shown as they are.
    #[test]
    fn shown_name_follows_adr054_item5() {
        let cases: [(&str, &str); 13] = [
            ("", ""),
            ("Alice", "Alice"),
            ("Zo\u{eb} \u{674e} \u{1f642}", "Zo\u{eb} \u{674e} \u{1f642}"),
            (" ~", " ~"),
            ("\u{a0}x", "\u{a0}x"),
            ("a\u{0}b", ""),
            ("a\u{1}", ""),
            ("a\u{1f}", ""),
            ("\u{7f}", ""),
            ("\u{80}", ""),
            ("x\u{9f}", ""),
            ("A\u{85}B", ""),
            ("line\n", ""),
        ];
        for (name, shown) in cases {
            assert_eq!(super::shown_name(name), shown, "{name:?}");
        }
    }

    #[cfg(feature = "kat")]
    use secmp_crypto::Zeroizing;
    #[cfg(feature = "kat")]
    use secmp_proto::prekeys::{IdentityKeys, IkDhSecret};

    #[cfg(feature = "kat")]
    use super::*;
    #[cfg(feature = "kat")]
    use crate::testutil::{E, Fixed, Fixture, entropy, ratchet_pair, unhex, vector_field};

    #[cfg(feature = "kat")]
    type R = Result<(), E>;

    /// The text of `src` with line ends normalised (the source scans read files checked out with either).
    #[cfg(feature = "kat")]
    fn normalised(src: &str) -> String {
        src.replace("\r\n", "\n")
    }

    /// A handshake profile.
    #[cfg(feature = "kat")]
    fn wire_profile(name: &str) -> Result<WireProfile, E> {
        Ok(WireProfile::new(name, None)?)
    }

    /// A contact row with `fingerprint` (the identity bytes are a stand-in: the row, not the key, is under test).
    #[cfg(feature = "kat")]
    fn put_row(fx: &Fixture, id: i64, fingerprint: &[u8; 32]) -> R {
        let store = fx.profile.store();
        let mut s = store.lock().map_err(|_| "lock")?;
        s.txn(|tx| {
            secmp_store::contacts::put_contact(
                tx,
                &secmp_store::contacts::Contact {
                    id,
                    iks: b"stand-in",
                    fingerprint,
                    display_name: None,
                    verified: false,
                    routes: None,
                    queues: None,
                    state: STATE_ACTIVE,
                    profile: None,
                },
            )
        })?;
        Ok(())
    }

    /// PR-04 (RT-3; `docs/03:356` "MUST NOT key … on `IK_sig` alone"): two handshakes whose `IKSPublic` share the signing
    /// half and differ in `ik_dh` make two contacts with distinct ids and distinct display keys — no event, nothing merged
    /// — and no code of `contacts.rs` (here and in the store) names the signing half.
    #[cfg(feature = "kat")]
    #[test]
    fn identity_is_whole_iks() -> R {
        let mut e = entropy(4);
        let fx = Fixture::new("pr04", &mut e)?;
        let contacts = Contacts::new(fx.profile.store(), fx.profile.fingerprint()?);
        let first = IdentityKeys::generate(&mut e)?;
        let mut second = first.public().clone();
        second.ik_dh = IkDhSecret::generate(&mut e)?.public_key()?;
        assert!(second != *first.public());
        assert_eq!(second.ik_ed25519, first.public().ik_ed25519);

        let (a, ev_a) =
            contacts.add_from_handshake(first.public(), &wire_profile("same name")?, None)?;
        let (b, ev_b) = contacts.add_from_handshake(&second, &wire_profile("same name")?, None)?;
        assert!(
            ev_a.is_empty() && ev_b.is_empty(),
            "no duplicate: the identities differ"
        );
        assert_ne!(a, b);
        let list = contacts.list()?;
        assert_eq!(list.len(), 2);
        let keys: Vec<String> = list.iter().map(Contact::display_key).collect();
        assert_ne!(keys.first(), keys.get(1));
        assert!(
            list.iter()
                .all(|c| !c.verified && c.state == ContactState::Active)
        );

        // source scan: nothing is indexed by the signing half of an identity
        let needles = [concat!("ik_", "sig"), concat!("ik_", "ed25519")];
        for (path, src) in [
            ("client-core contacts.rs", include_str!("contacts.rs")),
            (
                "store contacts.rs",
                include_str!("../../secmp-store/src/contacts.rs"),
            ),
        ] {
            let src = normalised(src);
            // the test module may name them (it builds the shared-signing-half case)
            let product = src
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            for needle in needles {
                assert!(!product.contains(needle), "{path} names {needle}");
            }
        }
        Ok(())
    }

    /// PR-05 (§6.7 `docs/03:362-368`; frozen `vectors/sas.json`): contacts built from the vector fingerprints show the
    /// vector's 60 digits, byte for byte, on both sides.
    #[cfg(feature = "kat")]
    #[test]
    fn sas_matches_vectors() -> R {
        let json = include_str!("../../../vectors/sas.json");
        let mut e = entropy(5);
        let fx = Fixture::new("pr05", &mut e)?;
        for case in ["sas-0001", "sas-0002", "sas-0003"] {
            let fp = |k: &str| -> Result<[u8; 32], E> {
                Ok(unhex(&vector_field(json, case, k)?)?
                    .try_into()
                    .map_err(|_| "fp length")?)
            };
            let (fp_a, fp_b) = (fp("fp_a")?, fp("fp_b")?);
            let want = vector_field(json, case, "safety_number")?;
            assert_eq!(want.len(), 60);
            // side A holds B as a contact, side B holds A
            put_row(&fx, 1, &fp_b)?;
            put_row(&fx, 2, &fp_a)?;
            let a = Contacts::new(fx.profile.store(), fp_a);
            let b = Contacts::new(fx.profile.store(), fp_b);
            assert_eq!(
                a.safety_number(ContactId(1))?.as_str(),
                want,
                "{case} side A"
            );
            assert_eq!(
                b.safety_number(ContactId(2))?.as_str(),
                want,
                "{case} side B"
            );
        }
        Ok(())
    }

    /// PR-06 (§6.7 `docs/03:368`, Q158): the digits the user confirms and the QR of the peer verify; a QR with the
    /// fingerprints swapped and wrong digits do not.
    #[cfg(feature = "kat")]
    #[test]
    fn verify_by_digits_or_qr() -> R {
        let mut e = entropy(6);
        let fx = Fixture::new("pr06", &mut e)?;
        let (fp_own, fp_peer) = ([0x11_u8; 32], [0x22_u8; 32]);
        for id in 1..=4 {
            put_row(&fx, id, &fp_peer)?;
        }
        let me = Contacts::new(fx.profile.store(), fp_own);
        // the peer's side: it holds `me` as a contact and shows its own-first QR
        let peer_fx = Fixture::new("pr06-peer", &mut e)?;
        put_row(&peer_fx, 1, &fp_own)?;
        let peer = Contacts::new(peer_fx.profile.store(), fp_peer);
        let shown = peer.qr_text(ContactId(1))?;
        assert_eq!(
            shown,
            [b"SecMP-SAS/1".as_slice(), &fp_peer, &fp_own].concat()
        );

        let number = me.safety_number(ContactId(1))?;
        let digits = number.as_str().to_owned();
        let grouped: Vec<&str> = number.groups().collect();
        assert!(
            me.confirm_digits(ContactId(1), &grouped.join(" "))?,
            "digits, grouped for display"
        );
        assert!(me.get(ContactId(1))?.verified);
        assert!(me.confirm_qr(ContactId(2), &shown)?, "the peer's QR");
        assert!(me.get(ContactId(2))?.verified);
        let swapped = [b"SecMP-SAS/1".as_slice(), &fp_own, &fp_peer].concat();
        assert!(
            !me.confirm_qr(ContactId(3), &swapped)?,
            "swapped fingerprints"
        );
        let truncated = shown.get(..shown.len() - 1).ok_or("shown")?;
        assert!(!me.confirm_qr(ContactId(3), truncated)?, "truncated");
        assert!(!me.get(ContactId(3))?.verified);
        let mut wrong = digits.into_bytes();
        let last = wrong.last_mut().ok_or("digits")?;
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(
            !me.confirm_digits(ContactId(4), &String::from_utf8(wrong)?)?,
            "wrong digits"
        );
        assert!(!me.confirm_digits(ContactId(4), "")?, "no digits");
        assert!(!me.get(ContactId(4))?.verified);
        Ok(())
    }

    /// PR-07 [O-29] (ADR-044 (f) `docs/08:422`): a second handshake with an existing contact's identity creates a second,
    /// unverified contact and raises `Event::DuplicateIdentity`; the first contact is untouched — not merged, still verified.
    #[cfg(feature = "kat")]
    #[test]
    fn same_iks_as_existing_contact() -> R {
        let mut e = entropy(7);
        let fx = Fixture::new("pr07", &mut e)?;
        let contacts = Contacts::new(fx.profile.store(), fx.profile.fingerprint()?);
        let peer = IdentityKeys::generate(&mut e)?;
        let (first, events) =
            contacts.add_from_handshake(peer.public(), &wire_profile("peer")?, None)?;
        assert!(events.is_empty());
        let fp = contacts.get(first)?.fingerprint;
        let own = Fixture::new("pr07-peer", &mut e)?;
        // verify the first by the digits of the pair
        let theirs = Contacts::new(own.profile.store(), fp);
        put_row(&own, 1, &fx.profile.fingerprint()?)?;
        let digits = theirs.safety_number(ContactId(1))?.as_str().to_owned();
        assert!(contacts.confirm_digits(first, &digits)?);

        let (second, events) =
            contacts.add_from_handshake(peer.public(), &wire_profile("peer")?, None)?;
        assert_ne!(first, second);
        assert_eq!(
            events,
            [Event::DuplicateIdentity {
                existing: first,
                new: second
            }]
        );
        let list = contacts.list()?;
        assert_eq!(list.len(), 2, "nothing merged");
        assert!(
            list.iter()
                .find(|c| c.id == first)
                .is_some_and(|c| c.verified)
        );
        assert!(
            list.iter()
                .find(|c| c.id == second)
                .is_some_and(|c| !c.verified)
        );
        assert_eq!(
            list.first().map(|c| c.fingerprint),
            list.get(1).map(|c| c.fingerprint)
        );
        Ok(())
    }

    /// Killer (mutant of `ContactState::of`): a restored contact (state 1) lists as `ReinviteRequired` and refuses real
    /// sends with that error; a state no build writes is the uniform `Unavailable`.
    #[cfg(feature = "kat")]
    #[test]
    fn reinvite_required_state() -> R {
        let mut e = entropy(9);
        let fx = Fixture::new("pr-reinvite", &mut e)?;
        put_row(&fx, 1, &[7; 32])?;
        let store = fx.profile.store();
        store
            .lock()
            .map_err(|_| "lock")?
            .txn(|tx| set_contact_state(tx, 1, STATE_REINVITE_REQUIRED))?;
        let contacts = Contacts::new(fx.profile.store(), [1; 32]);
        assert_eq!(
            contacts.get(ContactId(1))?.state,
            ContactState::ReinviteRequired
        );
        assert_eq!(
            contacts.check_send(ContactId(1)),
            Err(Error::ReinviteRequired)
        );
        store
            .lock()
            .map_err(|_| "lock")?
            .txn(|tx| set_contact_state(tx, 1, 9))?;
        assert_eq!(contacts.list().err(), Some(Error::Unavailable));
        Ok(())
    }

    /// PR-08 (§7.6 Control code 1, ADR-054 item 4): `Control{1}` without an argument marks the contact removed; real sends
    /// are refused; the scheduler is not told — the conversation keeps preparing cells (dummies) as before; a Control with
    /// an argument, or another code, changes nothing.
    #[cfg(feature = "kat")]
    #[test]
    fn contact_removed_control() -> R {
        use secmp_proto::wire::cell::AppKind;

        use crate::scheduler::outbox::{MemOutbox, MemPersist};
        use crate::sessions::actor::Conversation;

        let mut e = entropy(8);
        let fx = Fixture::new("pr08", &mut e)?;
        let contacts = Contacts::new(fx.profile.store(), fx.profile.fingerprint()?);
        let peer = IdentityKeys::generate(&mut e)?;
        let (id, _) = contacts.add_from_handshake(peer.public(), &wire_profile("peer")?, None)?;
        let (a, ea, _b, _eb) = ratchet_pair(8)?;
        let vk = secmp_crypto::HybridVerifyingKey::from_bytes(
            peer.public().ik_ed25519.as_bytes(),
            peer.public().ik_mldsa65.as_slice(),
        )?;
        let mut conv = Conversation::new(
            a,
            MemOutbox::default(),
            MemPersist::default(),
            Fixed(ea),
            vk,
            0,
        );
        let _ = AppKind::Text;
        assert!(conv.prepare_direct(0).is_ok());
        assert_eq!(contacts.check_send(id), Ok(()));

        let body = |code, arg: &[u8]| ControlBody {
            code,
            arg: Zeroizing::new(arg.to_vec()),
        };
        assert!(
            !contacts.on_control(id, &body(ControlCode::ContactRemoved, b"x"))?,
            "an argument"
        );
        assert!(
            !contacts.on_control(id, &body(ControlCode::SessionResetRequest, b""))?,
            "another code"
        );
        assert_eq!(contacts.get(id)?.state, ContactState::Active);
        assert!(contacts.on_control(id, &body(ControlCode::ContactRemoved, b""))?);
        assert_eq!(contacts.get(id)?.state, ContactState::Removed);
        assert_eq!(contacts.check_send(id), Err(Error::Blocked));
        assert_eq!(contacts.check_send(ContactId(99)), Err(Error::Unavailable));

        // the schedule is unchanged: nothing real is pending, and the slots keep carrying dummies
        assert!(!conv.has_pending_real());
        assert!(conv.prepare_direct(10_000).is_ok());
        assert!(!conv.has_pending_real());
        Ok(())
    }
}
