// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The work of SecMP-TR's header trial and `(hk, n)` lookup (spec §7.4) through the public `RatchetState::decrypt`,
//! read from the feature-`kat` counting accessor `tr::TRIAL_COUNTS_KAT` = `(header AEAD-open attempts, skipped
//! entries read)` (M5 TEST-SPEC b7 rows G-01, G-02; M4 review R-42, campaign R-58/R-59, docs/01 RR-17).
//!
//! - G-01 `tr_header_trial_open_tries_every_key`: whichever key opens the header — the first or the last distinct
//!   skipped header key, `hk_r`, `nhk_r` or none — the trial opens under every candidate: `|distinct skipped hks| + 2`
//!   AEAD opens, an absent `hk_r` costing one dummy open.
//! - G-02 `tr_skipped_lookup_touches_every_entry`: whether `(hk, n)` matches the first, the middle or the last entry of
//!   `skipped`, or none, the lookup reads every entry's message key exactly once: `|skipped|` reads. The read goes
//!   through the counting accessor `SkippedKey::mk`, the only read of an entry's `mk` outside `tr::state`, so a load
//!   of the matching entry's `mk` by its index (the dependence campaign R-58 removed) reads one more.
//!
//! The states are built through the public API with OS randomness: A (initiator) and B (responder) of one session;
//! B's `skipped` and its header keys are read from the `RatchetStateV1` encoding (layout in `src/tr/state.rs`) and
//! from `receiving_header_keys_kat`.

use secmp_crypto::{MSG_TAG_LEN, MlKem768Dk, SecretBytes, X25519Secret};
use secmp_proto::Error;
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{RatchetState, TRIAL_COUNTS_KAT};

/// The session binding.
const SB: [u8; 32] = [0x47; 32];
/// The cell length (spec §4.2 `CELL_LEN`).
const CELL_LEN: usize = 4096;

/// A fresh session (§7.2): the initiator A and the responder B.
fn session() -> (RatchetState, RatchetState) {
    let sk = SecretBytes::random().unwrap();
    let spk = X25519Secret::generate().unwrap();
    let rpk = MlKem768Dk::generate().unwrap();
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
    let a = RatchetState::init_initiator(&sk, &SB, &spk_pub, &rpk_ek).unwrap();
    let b = RatchetState::init_responder(&sk, &SB, spk, rpk).unwrap();
    (a, b)
}

/// The sender's next cell (a Dummy) and its new state.
fn send(s: RatchetState) -> (RatchetState, Vec<u8>) {
    let (s, cell) = s
        .encrypt(&dummy())
        .map_err(|r| r.error())
        .unwrap()
        .persist(|_| Ok::<(), Error>(()))
        .unwrap();
    (s, cell.as_bytes().to_vec())
}

/// `s` accepts `cell`; the committed new state.
fn receive(s: RatchetState, cell: &[u8]) -> RatchetState {
    s.decrypt(cell)
        .map_err(|r| r.error())
        .unwrap()
        .commit(|_| Ok::<(), Error>(()))
        .unwrap()
        .0
}

/// An independent copy of `s` through its encoding.
fn copy(s: &RatchetState) -> RatchetState {
    RatchetState::from_bytes(&s.to_bytes().unwrap()).unwrap()
}

/// What one `decrypt` of `cell` on a copy of `s` did: the committed new state if accepted (the uniform
/// `Error::Rejected` otherwise), and `TRIAL_COUNTS_KAT` after it — set to `(u32::MAX, u32::MAX)` before, so a
/// decryption that does not reset and count leaves them there.
fn run(s: &RatchetState, cell: &[u8]) -> (Option<RatchetState>, (u32, u32)) {
    let s = copy(s);
    TRIAL_COUNTS_KAT.set((u32::MAX, u32::MAX));
    let result = s.decrypt(cell);
    let counts = TRIAL_COUNTS_KAT.get();
    let state = match result {
        Ok(opened) => Some(opened.commit(|_| Ok::<(), Error>(())).unwrap().0),
        Err(refused) => {
            assert_eq!(refused.error(), Error::Rejected, "uniform rejection");
            None
        }
    };
    (state, counts)
}

/// A cursor over a `RatchetStateV1` encoding.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .expect("RatchetStateV1 too short");
        self.0 = tail;
        head
    }

    /// `opt(x)`: a presence byte and, if 1, `n` bytes.
    fn skip_opt(&mut self, n: usize) {
        let flag = self.take(1);
        assert!(matches!(flag, [0 | 1]), "presence byte {flag:?}");
        if flag == [1] {
            self.take(n);
        }
    }
}

/// The skipped entries `(hk, n)` of `s` in insertion order, from its `RatchetStateV1` encoding (`fmt ‖ sb ‖ rk ‖
/// dh_s.sk ‖ opt(dh_r) ‖ kem_s.seed ‖ opt(kem_r) ‖ opt(last_ct_r) ‖ opt(ct_s) ‖ opt(ck_s) … opt(nhk_r) ‖ n_s ‖ n_r
/// ‖ pn ‖ count u16 ‖ { hk ‖ n ‖ mk } × count`).
fn skipped(s: &RatchetState) -> Vec<([u8; 32], u32)> {
    let encoded = s.to_bytes().unwrap();
    let mut c = Cursor(&encoded);
    assert_eq!(c.take(1), [1], "format byte");
    c.take(96); // sb ‖ rk ‖ dh_s.sk
    c.skip_opt(32); // dh_r
    c.take(64); // kem_s.seed
    c.skip_opt(1184); // kem_r
    c.skip_opt(1088); // last_ct_r
    c.skip_opt(1088); // ct_s
    for _ in 0..6 {
        c.skip_opt(32); // ck_s, ck_r, hk_s, hk_r, nhk_s, nhk_r
    }
    c.take(12); // n_s ‖ n_r ‖ pn
    let count = u16::from_be_bytes(c.take(2).try_into().unwrap());
    let entries = (0..count)
        .map(|_| {
            let entry = c.take(68);
            let (hk, rest) = entry.split_first_chunk::<32>().unwrap();
            let (n, _mk) = rest.split_first_chunk::<4>().unwrap();
            (*hk, u32::from_be_bytes(*n))
        })
        .collect();
    assert!(c.0.is_empty(), "RatchetStateV1 fully consumed");
    entries
}

/// `x` as a `u32` count.
fn to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap()
}

/// B holding the skipped keys of A's chains `1 … layout.len()` — chain i contributes `layout[i − 1]` entries
/// `(hk_i, 0) … (hk_i, layout[i − 1] − 1)` — and A's cells for every candidate of B's header trial.
struct Fixture {
    b: RatchetState,
    /// A's undelivered cells, one per entry of B's `skipped`, in insertion order.
    entries: Vec<Vec<u8>>,
    /// A's delivered last cell of chain 1 (`n = layout[0]`, B's step onto chain 1): it opens under the first skipped
    /// header key, and `(hk_1, layout[0])` is not stored.
    delivered: Vec<u8>,
    /// A's cell `n = 1` of the chain under B's `hk_r`.
    current: Vec<u8>,
    /// A's cell `n = 0` of the chain under B's `nhk_r`.
    next: Vec<u8>,
}

/// On each of A's chains 1 … `layout.len()`, A sends `n = 0 … k` and B receives only `n = k` (its DH step stores
/// `(hk_i, 0) … (hk_i, k − 1)`), then B replies and A's DH step starts the next chain. B receives the next chain's
/// `n = 0` (its current chain, `hk_r`) and replies once more, so A's chain after that is under B's `nhk_r`. The shape
/// is checked: `|skipped|` = Σ layout, grouped by chain in insertion order with `n = 0 …`, `hk_r` and `nhk_r`
/// present and neither a skipped chain's key.
fn fixture(layout: &[u32]) -> Fixture {
    let (mut a, mut b) = session();
    let mut entries = Vec::new();
    let mut delivered = None;
    for &k in layout {
        for _ in 0..k {
            let (next_a, cell) = send(a);
            a = next_a;
            entries.push(cell);
        }
        let (next_a, last) = send(a);
        b = receive(b, &last);
        delivered.get_or_insert(last);
        let (next_b, reply) = send(b);
        b = next_b;
        a = receive(next_a, &reply);
    }
    let (a1, d0) = send(a);
    let (a2, current) = send(a1);
    b = receive(b, &d0);
    let (b, reply) = send(b);
    let (_, next) = send(receive(a2, &reply));

    let stored = skipped(&b);
    assert_eq!(stored.len(), entries.len(), "|skipped| = Σ layout");
    let groups: Vec<Vec<u32>> = stored
        .chunk_by(|x, y| x.0 == y.0)
        .map(|g| g.iter().map(|e| e.1).collect())
        .collect();
    let want: Vec<Vec<u32>> = layout.iter().map(|&k| (0..k).collect()).collect();
    assert_eq!(groups, want, "skipped grouped by chain, n = 0 … k − 1");
    let (hk_r, nhk_r) = b.receiving_header_keys_kat();
    let (hk_r, nhk_r) = (
        *hk_r.expect("hk_r set").expose_secret(),
        *nhk_r.expect("nhk_r set").expose_secret(),
    );
    assert_ne!(hk_r, nhk_r);
    assert!(
        stored.iter().all(|(hk, _)| *hk != hk_r && *hk != nhk_r),
        "hk_r and nhk_r are not skipped chains' keys"
    );
    Fixture {
        b,
        entries,
        delivered: delivered.expect("a non-empty layout"),
        current,
        next,
    }
}

/// `cell` with the first byte of its body tag (the cell's last `MSG_TAG_LEN` bytes, spec §7.5) flipped: the header
/// still opens, the body MAC fails.
fn wrong_body_tag(cell: &[u8]) -> Vec<u8> {
    let mut wrong = cell.to_vec();
    let byte = wrong
        .get_mut(CELL_LEN.checked_sub(MSG_TAG_LEN).unwrap())
        .unwrap();
    *byte ^= 1;
    wrong
}

/// G-01 (R-42, campaign R-59, docs/01 RR-17; spec §7.4): for 1, 3 and 5 distinct skipped header keys (states with
/// `hk_r` and `nhk_r` set), decryptions whose header opens under the first distinct skipped key, the last one (also
/// with the body tag wrong: rejected at the MAC), `hk_r`, `nhk_r` and no key perform `|distinct| + 2` AEAD opens
/// every time; on a fresh responder (`hk_r` absent, `skipped` empty) the absent key costs one dummy open: 2 opens,
/// for the first message (under `nhk_r`) and for a cell no key opens.
#[test]
fn tr_header_trial_open_tries_every_key() {
    for layout in [&[2_u32][..], &[3, 1, 2], &[1, 2, 1, 1, 2]] {
        let f = fixture(layout);
        let want = to_u32(layout.len()).checked_add(2).unwrap();
        let first = f.entries.first().unwrap();
        let last = f.entries.last().unwrap();
        let none = vec![0x5a; CELL_LEN];
        for (what, cell, accepted) in [
            ("first skipped hk", first, true),
            ("last skipped hk", last, true),
            (
                "last skipped hk, body tag wrong",
                &wrong_body_tag(last),
                false,
            ),
            ("hk_r", &f.current, true),
            ("nhk_r", &f.next, true),
            ("none", &none, false),
        ] {
            let (state, (opens, _)) = run(&f.b, cell);
            assert_eq!(state.is_some(), accepted, "{layout:?}, {what}: accepted");
            assert_eq!(opens, want, "{layout:?}, {what}: header AEAD-open attempts");
        }
    }

    // an absent key costs one dummy open: B before its first receive has `hk_r = None` and no skipped key
    let (a, b) = session();
    assert!(b.receiving_header_keys_kat().0.is_none() && b.receiving_header_keys_kat().1.is_some());
    assert!(skipped(&b).is_empty());
    let (_, m0) = send(a);
    let none = vec![0x5a; CELL_LEN];
    for (what, cell, accepted) in [("nhk_r (first message)", &m0, true), ("none", &none, false)] {
        let (state, (opens, reads)) = run(&b, cell);
        assert_eq!(
            state.is_some(),
            accepted,
            "fresh responder, {what}: accepted"
        );
        assert_eq!(
            (opens, reads),
            (2, 0),
            "fresh responder, {what}: (opens, entries read)"
        );
    }
}

/// G-02 (R-42, campaign R-58): on states with 6 and 7 skipped entries over 3 and 2 header keys, decryptions where
/// `(hk, n)` matches the first, the middle and the last entry (accepted: exactly that entry leaves `skipped`; and the
/// middle one with the body tag wrong: rejected at the MAC) and where nothing matches — no key opens; a skipped key
/// opens but `(hk, n)` is not stored (the replay of a delivered cell, and of an entry consumed just before); `hk_r`
/// opens; `nhk_r` opens — read the message key of every entry once: `|skipped|` reads in every case.
#[test]
fn tr_skipped_lookup_touches_every_entry() {
    for layout in [&[3_u32, 1, 2][..], &[4, 3]] {
        let f = fixture(layout);
        let stored = skipped(&f.b);
        let all = to_u32(stored.len());
        let middle = stored.len() / 2;
        for (what, at) in [
            ("first entry", 0),
            ("middle entry", middle),
            ("last entry", stored.len().checked_sub(1).unwrap()),
        ] {
            let (state, (_, reads)) = run(&f.b, f.entries.get(at).unwrap());
            let mut remaining = stored.clone();
            remaining.remove(at);
            assert_eq!(
                state.as_ref().map(skipped),
                Some(remaining),
                "{layout:?}, {what}: that entry consumed"
            );
            assert_eq!(reads, all, "{layout:?}, {what}: skipped entries read");
        }
        let (state, (_, reads)) = run(&f.b, &wrong_body_tag(f.entries.get(middle).unwrap()));
        assert!(
            state.is_none(),
            "{layout:?}, middle entry, body tag wrong: rejected"
        );
        assert_eq!(
            reads, all,
            "{layout:?}, middle entry, body tag wrong: skipped entries read"
        );

        let none = vec![0x5a; CELL_LEN];
        for (what, cell, accepted) in [
            ("no key opens", &none, false),
            ("skipped key opens, (hk, n) not stored", &f.delivered, false),
            ("hk_r opens", &f.current, true),
            ("nhk_r opens", &f.next, true),
        ] {
            let (state, (_, reads)) = run(&f.b, cell);
            assert_eq!(
                state.is_some(),
                accepted,
                "{layout:?}, no match, {what}: accepted"
            );
            assert_eq!(
                reads, all,
                "{layout:?}, no match, {what}: skipped entries read"
            );
        }

        // the entry consumed just before: the skipped key opens again, the entry is gone
        let first = f.entries.first().unwrap();
        let consumed = receive(copy(&f.b), first);
        let (state, (_, reads)) = run(&consumed, first);
        assert!(
            state.is_none(),
            "{layout:?}, replay of a consumed entry: rejected"
        );
        assert_eq!(
            reads,
            all.checked_sub(1).unwrap(),
            "{layout:?}, replay of a consumed entry: skipped entries read"
        );
    }
}
