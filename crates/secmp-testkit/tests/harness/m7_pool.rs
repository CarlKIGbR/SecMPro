// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-C1, the spare-queue pool in the product (D4′, `D4-ANALYSIS.md`; spec §10.6 (2), (3)): the stored spares (`relays.pool`)
//! are the scheduler pool's — adopted at an open, handed out by name to an invitation — and the scheduler's own delayed
//! `QUEUE_NEW` creates the replacements. QP-01…QP-05 and AI-01 (the scheduler's pool on its own) stay as they are.

use secmp_client_core::invitations::SparePool;
use secmp_client_core::scheduler::core::LinkKind;
use secmp_client_core::scheduler::types::{ControlKind, QueueId, RelayId};
use secmp_testkit::harness::{Dir, START_UNIX, VirtualDriver};
use secmp_transport::RecvCap;

use super::m6_common::{driver, frames_of, run_until_link_up};
use super::m7_world::{Party, add_party, hub};

/// What a host does at an open (the runtime's start): the hub's stored spares are adopted by the scheduler as created, its id
/// counter is floored above every stored id, and the missing spares are scheduled.
fn open_bridge(d: &mut VirtualDriver, p: &Party) {
    let start = hub(d, p.idx).bridge_pool().unwrap();
    let now = d.now();
    let c = d.client(p.idx);
    c.sched.floor_queue_ids(start.floor);
    for (queue, seed) in &start.spares {
        c.sched
            .adopt_pool_queue(now, start.relay, *queue, RecvCap::from_seed(seed).unwrap())
            .unwrap();
    }
    c.sched.manage_pool(now, start.relay).unwrap();
}

fn creations(d: &VirtualDriver, i: usize) -> Vec<(u64, QueueId)> {
    d.client_ref(i)
        .controls_started
        .iter()
        .filter_map(|(at, _, k)| match k {
            ControlKind::QueueNew(q) => Some((*at, *q)),
            _ => None,
        })
        .collect()
}

/// M7-C1 (D4′ (a), (d), 4): at an open the stored spares are adopted: each is fetched on a link of its own at `P_POOL` (80 s,
/// as QP-02), the pool counts them, and no `QUEUE_NEW` runs for them — they exist on the relay (the restart case of
/// `D4-ANALYSIS.md` §4); nothing is missing, so nothing is scheduled.
#[test]
fn adopted_spares_fetched_at_pool_period_no_queue_new() {
    let mut d = driver();
    let host = add_party(&mut d, "pool-open", 2, 11);
    assert_eq!(hub(&mut d, host.idx).spares().unwrap(), 2);
    open_bridge(&mut d, &host);
    assert_eq!(d.client_ref(host.idx).sched.pool_spares(RelayId(1)), 2);
    let (slot, _) = run_until_link_up(&mut d, host.idx, LinkKind::Recv);
    let t = d.now();
    d.run_until(t.saturating_add(900_000));
    let fetches: Vec<u64> = frames_of(&d, host.idx, Dir::C2R, slot)
        .iter()
        .map(|e| e.t_ms)
        .collect();
    assert!(fetches.len() >= 10, "{} FETCHes", fetches.len());
    for pair in fetches.windows(2) {
        assert_eq!(pair.get(1).unwrap() - pair.first().unwrap(), 80_000);
    }
    assert!(
        creations(&d, host.idx).is_empty(),
        "no QUEUE_NEW at the open: {:?}",
        creations(&d, host.idx)
    );
    assert!(d.client_ref(host.idx).hub_errors.is_empty());
    assert_eq!(d.client_ref(host.idx).sched.pool_spares(RelayId(1)), 2);
}

/// M7-C1 (D4′ (c), (b), (e); QP-03 with a hub): an invitation takes the NAMED oldest spare — its queue is the pool's, its link
/// moves to the invitation's period — with no `QUEUE_NEW` at that moment; the replacement is the scheduler's own, due ≥ 60 s
/// after the hand-out, under an id above every stored one, and its seeds are in the stored pool when it is done.
#[test]
fn invitation_takes_named_spare_refill_delayed() {
    let mut d = driver();
    let host = add_party(&mut d, "pool-take", 2, 7);
    open_bridge(&mut d, &host);
    d.run_until(120_000);
    assert!(creations(&d, host.idx).is_empty());
    let t = d.now();
    let issued = hub(&mut d, host.idx)
        .invite(START_UNIX + 5 * 86_400)
        .unwrap();
    let taken = hub(&mut d, host.idx)
        .invitation_queue(&issued.invitation.ld_id)
        .unwrap();
    assert_eq!(taken, QueueId(1), "the oldest stored spare");
    d.run_until(t.saturating_add(30_000));
    let c = d.client_ref(host.idx);
    assert!(c.sched.has_queue(taken));
    assert_eq!(
        c.sched.pool_spares(RelayId(1)),
        1,
        "handed out, not yet replaced"
    );
    assert!(
        c.controls_done
            .iter()
            .any(|(_, k)| matches!(k, ControlKind::LinkPut(_))),
        "the LINK_PUT ran"
    );
    assert!(
        creations(&d, host.idx).is_empty(),
        "no QUEUE_NEW at or near the hand-out"
    );
    // the replacement: delayed U[1 min, 60 min], then created with seeds the store holds
    d.run_until(t.saturating_add(3_700_000));
    let made = creations(&d, host.idx);
    assert_eq!(made.len(), 1, "{made:?}");
    let (at, replacement) = *made.first().unwrap();
    assert!(
        at >= t + 60_000,
        "the replacement starts ≥ 1 min later: {at} vs {t}"
    );
    assert!(
        replacement.0 >= 3,
        "above every stored id (1, 2): {replacement:?}"
    );
    let store = hub(&mut d, host.idx).profile_store();
    let seeds = SparePool::new(store).seeds(RelayId(1)).unwrap();
    assert!(seeds.iter().any(|(q, _, _)| *q == replacement), "persisted");
    assert_eq!(seeds.len(), 2);
    let c = d.client_ref(host.idx);
    assert!(
        c.controls_done
            .iter()
            .any(|(_, k)| *k == ControlKind::QueueNew(replacement)),
        "the QUEUE_NEW ran"
    );
    assert_eq!(c.sched.pool_spares(RelayId(1)), 2, "replaced");
    assert!(c.hub_errors.is_empty(), "{:?}", c.hub_errors);
}
