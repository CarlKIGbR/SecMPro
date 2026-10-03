// SPDX-License-Identifier: AGPL-3.0-or-later
//! The responder of SecMP-HX (spec §6.5 grouping, §6.6 steps 1–4): the inviter's side.
//!
//! **Atomicity.** Everything `accept` computes lives on working copies; the only side effect is the commit of
//! step 4 (`commit_accept`: OPK deletion and record consumption), which is the last operation. Every rejection therefore leaves the store, the record and the caller's
//! state as they were, and "log nothing identifying" (§6.6 step 3) holds because nothing here logs.
//!
//! **One uniform error.** Every rejection of untrusted input is [`Error::Rejected`], whichever check failed;
//! [`Error::Unavailable`] occurs only if the ratchet's sending half could not draw randomness after the
//! `first_msg` MAC verified (the caller neither acknowledges nor deletes anything and retries).

use secmp_crypto::{Caead, ConstantTimeEq, Label, MlKem1024Ct, SecretBytes};

use super::derive::{Shared, TranscriptInputs, k_id, session_key, transcript};
use super::{ResponderKeys, dh_checked};
use crate::codec::{Decode, Encode, Zeroizing};
use crate::error::{Error, Result};
use crate::inv::derive_k_inv;
use crate::prekeys::{InvitationRecord, PrekeyStore};
use crate::sizes::{HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, NONCE_LEN};
use crate::tr::{Entropy, RatchetState};
use crate::wire::Id;
use crate::wire::cell::{Cell, ContentBody, RouteDescriptor};
use crate::wire::hx::{HandshakeCellPlaintext, Inner, Outer};
use crate::wire::inv::{IksPublic, Profile};

/// At most this many partially received envelopes are held while grouping; the oldest is evicted (ADR-044 (c)).
pub const MAX_PARTIAL_GROUPS: usize = 8;

/// At most this many complete groups are recorded as processed in one [`Responder::accept`] call (ADR-044 (c), M4
/// review C-10): ⌊`QUEUE_CAPACITY` / 3⌋ = ⌊128 / 3⌋ (`docs/03:168`), the most complete groups one full invitation queue
/// holds. A call that completes more stops there and rejects (fail-closed).
pub const MAX_PROCESSED_GROUPS: usize = 42;
const _: () = assert!(MAX_PROCESSED_GROUPS >= 128 / 3);

#[cfg(feature = "kat")]
std::thread_local! {
    /// The reject-site tag of the last [`Responder::accept`] on this thread (feature `kat`; M3 review R-45, F19), read
    /// with `ACCEPT_SITE_KAT.get()`: the constant-time bench checks before measuring that each class of a target is
    /// refused at the step the target claims. The tag names the step that was running when `accept` returned; it is
    /// set when a step begins, so after a rejection it names the step that rejected:
    ///
    /// - `"no complete group"` — set by `accept` first: §6.5 trial-opening and grouping (no group completed);
    /// - `"outer"` — `drive`, before §6.6 step 1 on a complete group: `Outer`, `spk_id`/`opk_id`, the prekeys;
    /// - `"x25519"` — on entry to `dh_checked` (DH3, DH4 in step 2; DH1, DH2 in step 3; the all-zero check of
    ///   §6.4); the decapsulations after DH4 cannot fail;
    /// - `"inner open"` — on entry to [`crate::hx::k_id`], whose KDF cannot fail: `CAEAD.Open` of `inner_ct` under
    ///   `K_id` (step 2);
    /// - `"inner checks"` — after that open: the `Inner` decoder and the reflected-identity check (ADR-044 (f));
    /// - `"first_msg decrypt"` — on entry to [`crate::hx::session_key`], whose KDF cannot fail: the prekey copies
    ///   (`Unavailable` only), the TR responder initialisation (§7.2; never `Rejected` for stored keys) and §7.4
    ///   Decrypt of `first_msg` (step 3);
    /// - `"first_msg checks"` — after that Decrypt: the counters, the commit, the Content and the routes (ADR-044
    ///   (e));
    /// - `"opk delete"` — `drive`, step 4 (`commit_accept`).
    ///
    /// `k_id`, `session_key` and `dh_checked` set it on the initiator's side too; it is meaningful after `accept`
    /// only. `None` before the first call on this thread. Without `kat` neither the tag nor any statement setting it
    /// exists. (A thread-local rather than accessor functions: the mutation gate builds this crate without `kat`, so
    /// the body of a `kat`-only function would only add surviving mutants.)
    pub static ACCEPT_SITE_KAT: core::cell::Cell<Option<&'static str>> = const { core::cell::Cell::new(None) };
}

/// What a successful [`Responder::accept`] yields (§6.6 step 4).
pub struct Accepted {
    /// The ratchet state after decrypting `first_msg` (§7.4): the responder side of the session. It holds none
    /// of the prekey secrets: the DH step replaced `SPK_dh` and `RPK_kem` (CLAUDE.md §1.3).
    pub state: RatchetState,
    /// `IKSPublic_I`: the contact is stored as **unverified**.
    pub peer: IksPublic,
    /// The initiator's reply routes from `first_msg`'s Handshake content, byte-identical to what it sent (§6.5).
    pub routes: Zeroizing<Vec<RouteDescriptor>>,
    /// The initiator's profile from the Handshake content.
    pub profile: Profile,
}

/// The responder (the inviter).
pub struct Responder;

/// The chunks received so far for one `init_id`, of any chunk type `C` (the responder stores the 4006-byte chunks;
/// the Kani harnesses of the grouping and of `drive` use a small stand-in, which is why they are generic).
pub(crate) struct Group<K, C> {
    pub(crate) init_id: K,
    pub(crate) chunks: [Option<C>; 3],
}

impl<K, C> Group<K, C> {
    pub(crate) fn complete(&self) -> bool {
        self.chunks.iter().all(Option::is_some)
    }
}

/// The partial groups held while grouping: a fixed array of `N` slots in arrival order (oldest first), no `Vec`
/// (the Kani harnesses of the grouping and of `drive` unroll it with a small `N`).
pub(crate) struct Groups<K, C, const N: usize> {
    slots: [Option<Group<K, C>>; N],
    len: usize,
}

impl<K: PartialEq, C, const N: usize> Groups<K, C, N> {
    pub(crate) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    #[cfg(kani)]
    pub(crate) fn get(&self, at: usize) -> Option<&Group<K, C>> {
        self.slots.get(at)?.as_ref()
    }

    /// [`Groups::remove`] for the grouping harness, which removes a completed group as [`drive`] does.
    #[cfg(kani)]
    pub(crate) fn remove_completed(&mut self, at: usize) -> Option<Group<K, C>> {
        self.remove(at)
    }

    fn position(&self, init_id: &K) -> Option<usize> {
        self.slots
            .iter()
            .take(self.len)
            .position(|g| g.as_ref().is_some_and(|g| g.init_id == *init_id))
    }

    /// Remove slot `at`, shifting the younger groups down (order kept).
    fn remove(&mut self, at: usize) -> Option<Group<K, C>> {
        if at >= self.len {
            return None;
        }
        let removed = self.slots.get_mut(at)?.take();
        let mut i = at;
        while i.checked_add(1)? < self.len {
            let next = self.slots.get_mut(i.checked_add(1)?)?.take();
            *self.slots.get_mut(i)? = next;
            i = i.checked_add(1)?;
        }
        self.len = self.len.checked_sub(1)?;
        removed
    }

    fn push(&mut self, group: Group<K, C>) -> Option<usize> {
        let at = self.len;
        *self.slots.get_mut(at)? = Some(group);
        self.len = self.len.checked_add(1)?;
        Some(at)
    }
}

/// Add chunk `i` (< 3) of `init_id` (§6.5, ADR-044 (c)): a duplicate `(init_id, i)` is ignored whatever its bytes
/// (identical: nothing to do; differing: first-seen wins); a new `init_id` evicts the oldest partial group once the
/// `N` slots ([`MAX_PARTIAL_GROUPS`]) are full. Returns the index of the group if it is now complete. A chunk of an
/// `init_id` whose group was already processed in the same call never reaches `insert` ([`drive`] drops it, M4
/// review C-10), so a rejected group does not form again.
pub(crate) fn insert<K: PartialEq, C, const N: usize>(
    groups: &mut Groups<K, C, N>,
    init_id: K,
    i: usize,
    chunk: C,
) -> Option<usize> {
    if i >= 3 {
        return None;
    }
    let at = if let Some(at) = groups.position(&init_id) {
        at
    } else {
        if groups.len() >= N {
            groups.remove(0);
        }
        groups.push(Group {
            init_id,
            chunks: [None, None, None],
        })?
    };
    let group = groups.slots.get_mut(at)?.as_mut()?;
    let slot = group.chunks.get_mut(i)?;
    if slot.is_none() {
        *slot = Some(chunk);
    }
    group.complete().then_some(at)
}

/// The `init_id`s of the complete groups [`drive`] processed and rejected in one call (ADR-044 (c), M4 review C-10): a
/// fixed array of `R` slots, no `Vec` (the Kani harness of `drive` runs it as in production).
pub(crate) struct Processed<K, const R: usize> {
    ids: [Option<K>; R],
    len: usize,
}

impl<K: PartialEq, const R: usize> Processed<K, R> {
    pub(crate) const fn new() -> Self {
        Self {
            ids: [const { None }; R],
            len: 0,
        }
    }

    fn contains(&self, init_id: &K) -> bool {
        self.ids
            .iter()
            .take(self.len)
            .any(|x| x.as_ref() == Some(init_id))
    }

    /// Record `init_id`; `false` if all `R` slots are taken.
    fn push(&mut self, init_id: K) -> bool {
        let Some(slot) = self.ids.get_mut(self.len) else {
            return false;
        };
        *slot = Some(init_id);
        self.len = self.len.saturating_add(1);
        true
    }
}

/// The driver of §6.5 and §6.6 step 4 over already opened chunks `(init_id, i, chunk)`, in fetch order: group them
/// ([`insert`]); for each group that completes, in the order of completion, `process` it (§6.6 steps 1–3, reading
/// the store); the first group `process` accepts is the session: the OPK is deleted and the record consumed — the only call of
/// `commit_accept`, after `process` succeeded — and `process`'s value returned. A group `process` rejects is discarded
/// and the OPK kept; its `init_id` is recorded, and every later chunk of that `init_id` in this call is ignored — the
/// first complete group of an `init_id` is the one that counts (first-seen wins, ADR-044 (c); M4 review C-10; the
/// record lives for one call). Groups of other `init_id`s are still processed, up to [`MAX_PROCESSED_GROUPS`] rejected
/// ones (then the call rejects). If none is accepted the result is [`Error::Rejected`]; [`Error::Unavailable`] from
/// `process` is passed up at once. A failing `commit_accept` rejects, the OPK kept.
pub(crate) fn drive<K: PartialEq, C, T, S: PrekeyStore>(
    items: impl IntoIterator<Item = (K, usize, C)>,
    store: &mut S,
    opk_id: u32,
    ld_id: &Id,
    mut process: impl FnMut(&Group<K, C>, &S) -> Result<T>,
) -> Result<T> {
    let mut groups: Groups<K, C, MAX_PARTIAL_GROUPS> = Groups::new();
    let mut processed: Processed<K, MAX_PROCESSED_GROUPS> = Processed::new();
    for (init_id, i, chunk) in items {
        // a group of this init_id was processed and rejected in this call: it does not form again (ADR-044 (c))
        if processed.contains(&init_id) {
            continue;
        }
        let Some(done) = insert(&mut groups, init_id, i, chunk) else {
            continue;
        };
        let Some(group) = groups.remove(done) else {
            continue;
        };
        #[cfg(feature = "kat")]
        ACCEPT_SITE_KAT.set(Some("outer"));
        match process(&group, &*store) {
            Ok(accepted) => {
                // step 4: delete the OPK and consume the record (`commit_accept`) — the last operation; a failure keeps it and rejects
                #[cfg(feature = "kat")]
                ACCEPT_SITE_KAT.set(Some("opk delete"));
                store
                    .commit_accept(opk_id, ld_id)
                    .map_err(|_| Error::Rejected)?;
                return Ok(accepted);
            }
            Err(Error::Unavailable) => return Err(Error::Unavailable),
            // a rejected complete group is discarded and its init_id recorded; the OPK is kept (§6.6 step 3). More
            // rejected groups than a full queue holds: stop (fail-closed)
            Err(_) => {
                if !processed.push(group.init_id) {
                    return Err(Error::Rejected);
                }
            }
        }
    }
    Err(Error::Rejected)
}

impl Responder {
    /// §6.5 and §6.6: trial-open every cell of `cells` (the cells fetched from the invitation queue and retained
    /// for it) with `K_inv`; ignore what does not open or parse; group the chunks by `init_id`; for each group that
    /// completes, in the order of completion, run steps 1–3 — and on the first group that passes, step 4
    /// (`commit_accept`: delete the OPK, consume the record), and return the session.
    ///
    /// `record` is the invitation's record (§5.2). Expiry is the record lifecycle's: the caller offers only
    /// unexpired records ([`crate::prekeys::MemoryPrekeyStore::offered_records`], ADR-044 (d)).
    ///
    /// A group that completes but is rejected is discarded and the OPK kept; later groups are still processed. If
    /// no group passes, the result is [`Error::Rejected`], whether `cells` held garbage only, an incomplete group
    /// or a bad envelope.
    ///
    /// # Errors
    /// The uniform [`Error::Rejected`]; [`Error::Unavailable`] as described in the module documentation. The store
    /// is unchanged on every error.
    pub fn accept(
        cells: &[Cell],
        record: &InvitationRecord,
        store: &mut impl PrekeyStore,
        own_keys: &ResponderKeys<'_>,
        entropy: &mut impl Entropy,
    ) -> Result<Accepted> {
        #[cfg(feature = "kat")]
        ACCEPT_SITE_KAT.set(Some("no complete group"));
        let k_inv = derive_k_inv(&record.ld_id, &record.link_key)?;
        let ad_cell = [Label::HxInitcell.as_bytes(), record.ld_id.as_slice()].concat();
        // trial-open every cell with K_inv; anything that does not open or parse is ignored (garbage may come from
        // the relay or an invitation thief; it is never fatal)
        let opened = cells.iter().filter_map(|cell| {
            let p = open_cell(&k_inv, &ad_cell, cell)?;
            Some((p.init_id, usize::from(p.i), p.chunk))
        });
        drive(
            opened,
            store,
            record.opk_id,
            &record.ld_id,
            |group, store| process(group, record, store, own_keys, entropy),
        )
    }
}

/// `CAEAD.Open(K_inv, N_i, "SecMP-HX/1 initcell" ‖ ld_id, …)` and the `HandshakeCellPlaintext` decoder (`total` = 3,
/// `i` ≤ 2). `None` for a cell that does not open or parse.
fn open_cell(k_inv: &SecretBytes<32>, ad: &[u8], cell: &Cell) -> Option<HandshakeCellPlaintext> {
    let (n, com_ct) = cell.as_bytes().split_first_chunk::<NONCE_LEN>()?;
    let plaintext = Caead::open(k_inv, n, ad, com_ct).ok()?;
    HandshakeCellPlaintext::decode(&plaintext).ok()
}

/// §6.6 steps 1–3 on a complete group; no side effect.
fn process(
    group: &Group<Id, Box<[u8; HANDSHAKE_CHUNK_LEN]>>,
    record: &InvitationRecord,
    store: &impl PrekeyStore,
    own_keys: &ResponderKeys<'_>,
    entropy: &mut impl Entropy,
) -> Result<Accepted> {
    // Padded = chunk_0 ‖ chunk_1 ‖ chunk_2
    let mut padded = Zeroizing::new(Vec::with_capacity(
        HANDSHAKE_CHUNK_LEN.saturating_mul(usize::from(HANDSHAKE_CHUNKS)),
    ));
    for chunk in &group.chunks {
        padded.extend_from_slice(chunk.as_deref().ok_or(Error::Rejected)?);
    }

    // step 1: parse Outer (padding, version, low-order EK_I); `spk_id`/`opk_id` are this invitation's; the SPK is
    // retained and the OPK unused
    let outer = Outer::decode(&padded)?;
    if outer.spk_id != record.spk_id || outer.opk_id != record.opk_id {
        return Err(Error::Rejected);
    }
    let spk = store.spk(outer.spk_id).ok_or(Error::Rejected)?;
    let opk = store.opk(outer.opk_id).ok_or(Error::Rejected)?;

    // step 2: DH3, DH4, ss_spk, ss_opk -> K_id; open inner_ct
    let ek = outer.ek_i.as_bytes();
    let dh3 = dh_checked(spk.dh_secret(), ek)?;
    let dh4 = dh_checked(opk.dh_secret(), ek)?;
    let kem_signed = spk
        .kem_secret()
        .decapsulate(&MlKem1024Ct::from_bytes(outer.ct_spk.as_slice())?);
    let kem_onetime = opk
        .kem_secret()
        .decapsulate(&MlKem1024Ct::from_bytes(outer.ct_opk.as_slice())?);
    let k_id = k_id(
        &record.ld_id,
        &record.link_key,
        &dh3,
        &kem_signed,
        &dh4,
        &kem_onetime,
    )?;
    let ad_inner = [Label::HxInner.as_bytes(), record.ld_id.as_slice()].concat();
    let com_ct = [outer.inner_ct.com.as_slice(), outer.inner_ct.ct.as_slice()].concat();
    let inner_bytes = Caead::open(&k_id, &outer.inner_ct.n2, &ad_inner, &com_ct)?;
    #[cfg(feature = "kat")]
    ACCEPT_SITE_KAT.set(Some("inner checks"));
    // IKSPublic_I decodable with `ik_dh` not low-order; `first_msg` is a 4096-byte cell
    let inner = Inner::decode(&inner_bytes)?;
    // ADR-044 (f): a reflected identity is rejected
    let reflected = inner.iks.encode()?.ct_eq(&own_keys.iks.encode()?);
    if bool::from(reflected) {
        return Err(Error::Rejected);
    }

    // step 3: DH1, DH2, transcript, SK; TR responder (§7.2); decrypt first_msg (§7.4)
    let dh1 = dh_checked(spk.dh_secret(), inner.iks.ik_dh.as_bytes())?;
    let dh2 = dh_checked(own_keys.ik_dh.secret(), ek)?;
    let spk_dh = spk.dh_public()?;
    let spk_kem = spk.kem_public()?;
    let rpk_kem = spk.rpk_public()?;
    let opk_dh = opk.dh_public()?;
    let opk_kem = opk.kem_public()?;
    let transcript = transcript(&TranscriptInputs {
        iks_r: own_keys.iks,
        spk_id: outer.spk_id,
        spk_dh: &spk_dh,
        spk_kem: &spk_kem,
        rpk_kem: &rpk_kem,
        opk_id: outer.opk_id,
        opk_dh: &opk_dh,
        opk_kem: &opk_kem,
        iks_i: &inner.iks,
        ek_i: &outer.ek_i,
        ct_spk: &outer.ct_spk,
        ct_opk: &outer.ct_opk,
        ld_id: &record.ld_id,
    })?;
    let sk = session_key(
        &Shared {
            dh1,
            dh2,
            dh3,
            dh4,
            ss_spk: kem_signed,
            ss_opk: kem_onetime,
        },
        &transcript,
    )?;
    let state = RatchetState::init_responder(&sk, &transcript, spk.dh_copy()?, spk.rpk_copy()?)?;
    // §7.4 Decrypt with no fast-forward: `n ≠ 0` is rejected before any chain step (ADR-044 (e), M4 review C-9)
    let opened = state
        .decrypt_first_with(inner.first_msg.as_bytes(), entropy)
        .map_err(|refused| refused.error())?;
    #[cfg(feature = "kat")]
    ACCEPT_SITE_KAT.set(Some("first_msg checks"));
    // ADR-044 (e): the first message carries n = 0 and pn = 0
    if opened.header_counters() != (0, 0) {
        return Err(Error::Rejected);
    }
    let (state, plaintext) = opened
        .commit(|_| Ok::<(), Error>(()))
        .map_err(|_: Error| Error::Rejected)?;
    // §6.5 / §6.6 step 3: the content must be a Handshake (caps = 0 and a non-empty route list are the decoder's)
    let ContentBody::Handshake(handshake) = plaintext.content()?.body else {
        return Err(Error::Rejected);
    };
    // ADR-044 (e): at least one route of a known kind
    if !handshake
        .routes
        .iter()
        .any(|r| matches!(r, RouteDescriptor::RelayQueue(_)))
    {
        return Err(Error::Rejected);
    }
    Ok(Accepted {
        state,
        peer: inner.iks,
        routes: Zeroizing::new(handshake.routes),
        profile: handshake.profile,
    })
}

#[cfg(test)]
mod tests {
    use super::{Groups, MAX_PARTIAL_GROUPS, MAX_PROCESSED_GROUPS, drive, insert};
    use crate::error::{Error, Result};
    use crate::prekeys::{OpkSecrets, PrekeyStore, SpkGeneration};

    /// A store without keys for `drive`: it counts `commit_accept` calls and always commits.
    #[derive(Default)]
    struct Commits(u32);

    impl PrekeyStore for Commits {
        fn spk(&self, _spk_id: u32) -> Option<&SpkGeneration> {
            None
        }

        fn opk(&self, _opk_id: u32) -> Option<&OpkSecrets> {
            None
        }

        fn delete_opk(&mut self, _opk_id: u32) -> Result<()> {
            Err(Error::Rejected)
        }

        fn commit_accept(&mut self, _opk_id: u32, _ld_id: &[u8; 16]) -> Result<()> {
            self.0 = self.0.saturating_add(1);
            Ok(())
        }
    }

    /// `drive` over `items` with a `process` stub that rejects the groups whose first chunk is in `bad` and accepts
    /// the others: the result, the `init_id`s `process` saw (in order), and the commits.
    fn run(items: &[(u8, usize, u8)], bad: &[u8]) -> (Result<u8>, Vec<u8>, u32) {
        let mut store = Commits::default();
        let mut seen = Vec::new();
        let result = drive(
            items.iter().copied(),
            &mut store,
            1,
            &[0; 16],
            |group, _| {
                seen.push(group.init_id);
                match group.chunks.first().and_then(Option::as_ref) {
                    Some(tag) if bad.contains(tag) => Err(Error::Rejected),
                    _ => Ok(group.init_id),
                }
            },
        );
        (result, seen, store.0)
    }

    /// M4 review C-10 (R-24): the same input as `rejected_init_id_does_not_re_form_within_one_accept` through `drive`
    /// with a counting `process`: `[bogus₁(X), h₀, h₁, h₂, h₀, h₁, h₂]` (the bogus chunk 1 first) completes X once,
    /// rejected — `process` runs exactly once and nothing is committed; another `init_id` after it is still processed;
    /// more rejected groups than [`MAX_PROCESSED_GROUPS`] stop the call.
    #[test]
    fn drive_does_not_re_form_a_rejected_init_id() {
        let x = 7;
        // chunk tags: 0 = honest, 9 = the bogus chunk 1; the stub rejects a group whose chunk 1 is the bogus one
        let items = [
            (x, 1, 9),
            (x, 0, 0),
            (x, 1, 0),
            (x, 2, 0),
            (x, 0, 0),
            (x, 1, 0),
            (x, 2, 0),
        ];
        let mut store = Commits::default();
        let mut calls = 0_u32;
        let result = drive(
            items.iter().copied(),
            &mut store,
            1,
            &[0; 16],
            |group, _| {
                calls = calls.saturating_add(1);
                match group.chunks.get(1).and_then(Option::as_ref) {
                    Some(9) => Err(Error::Rejected),
                    _ => Ok(group.init_id),
                }
            },
        );
        assert_eq!(result.err(), Some(Error::Rejected));
        assert_eq!(calls, 1, "the group of X is processed once");
        assert_eq!(store.0, 0, "nothing committed");
        // the honest group alone, and after a rejected group of another init_id: accepted
        let honest = [(x, 0, 0), (x, 1, 0), (x, 2, 0)];
        assert_eq!(run(&honest, &[]), (Ok(x), vec![x], 1));
        let other: Vec<(u8, usize, u8)> = [(3, 0, 5), (3, 1, 5), (3, 2, 5)]
            .into_iter()
            .chain(honest)
            .collect();
        assert_eq!(run(&other, &[5]), (Ok(x), vec![3, x], 1));
        // the chunks of a rejected init_id that come later start no group, whatever their bytes
        let again: Vec<(u8, usize, u8)> = [
            (3, 0, 5),
            (3, 1, 5),
            (3, 2, 5),
            (3, 0, 0),
            (3, 1, 0),
            (3, 2, 0),
        ]
        .to_vec();
        assert_eq!(run(&again, &[5]), (Err(Error::Rejected), vec![3], 0));
        // MAX_PROCESSED_GROUPS rejected groups are recorded; one more stops the call before a later good group
        let limit = u8::try_from(MAX_PROCESSED_GROUPS).unwrap_or(u8::MAX);
        let many: Vec<(u8, usize, u8)> = (0..=limit)
            .flat_map(|id| (0..3).map(move |i| (id, i, 5)))
            .chain([(200, 0, 0), (200, 1, 0), (200, 2, 0)])
            .collect();
        let (result, seen, commits) = run(&many, &[5]);
        assert_eq!(result.err(), Some(Error::Rejected));
        assert_eq!(seen.len(), MAX_PROCESSED_GROUPS.saturating_add(1));
        assert_eq!(commits, 0);
        // one rejected group fewer: the good group after them is processed and committed
        let fewer: Vec<(u8, usize, u8)> = (0..limit)
            .flat_map(|id| (0..3).map(move |i| (id, i, 5)))
            .chain([(200, 0, 0), (200, 1, 0), (200, 2, 0)])
            .collect();
        assert_eq!(run(&fewer, &[5]).0, Ok(200));
    }

    type G = Groups<u8, u8, MAX_PARTIAL_GROUPS>;

    /// `n` partial groups (chunk 0 only) with `init_id` 1…`n`, in insertion order.
    fn partial(n: u8) -> G {
        let mut groups = G::new();
        for k in 1..=n {
            assert_eq!(insert(&mut groups, k, 0, k), None, "a partial group");
        }
        assert_eq!(groups.len(), usize::from(n));
        groups
    }

    /// The `init_id`s of the held groups, in slot order; a hole inside `len` shows as a short list.
    fn ids(groups: &G) -> Vec<u8> {
        groups
            .slots
            .iter()
            .take(groups.len())
            .filter_map(|g| g.as_ref().map(|g| g.init_id))
            .collect()
    }

    #[test]
    fn groups_remove_shifts_later_slots_in_order() {
        for n in [1_u8, 3, 8] {
            for at in 0..n {
                let mut groups = partial(n);
                let gone = at.saturating_add(1);
                let removed = groups.remove(usize::from(at));
                assert_eq!(removed.map(|g| g.init_id), Some(gone), "n={n} at={at}");
                let expected: Vec<u8> = (1..=n).filter(|k| *k != gone).collect();
                assert_eq!(ids(&groups), expected, "n={n} at={at}: order kept");
                assert_eq!(groups.len(), usize::from(n.saturating_sub(1)));
                assert!(
                    groups.slots.iter().skip(groups.len()).all(Option::is_none),
                    "n={n} at={at}: the freed slots are at the end"
                );
                // the chunk of every survivor moved with its group
                for g in groups.slots.iter().flatten() {
                    assert_eq!(g.chunks.first().and_then(Option::as_ref), Some(&g.init_id));
                }
            }
            let mut groups = partial(n);
            assert!(groups.remove(usize::from(n)).is_none(), "past the end");
            assert_eq!(groups.len(), usize::from(n));
        }
    }

    #[test]
    fn groups_remove_on_empty_store_is_none() {
        let mut groups = G::new();
        assert!(groups.remove(0).is_none());
        assert!(groups.remove(7).is_none());
        assert_eq!(groups.len(), 0);
    }
}
