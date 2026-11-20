// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7 B-SC SC-04 (FIN5b-1): the logical link id. `Purpose::Link` and `LinkEvent::{Up, TornDown}` carry the logical link a
//! connection serves, stable across the link's reconnects, and the reconnect oracle (`m6_sim::check_reconnects`) matches
//! each teardown to its own link's reconnect.

use std::collections::{BTreeMap, BTreeSet};

use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::Purpose;
use secmp_client_core::scheduler::types::{LinkEvent, LinkId, LogicalLinkId, Reason};

use crate::m6_activity::Scenario;
use crate::m6_common::evidence;
use crate::m6_sim::{ORACLE_END, check_reconnects, oracle_bound, oracle_connect, oracle_down};
use crate::m6_tokio::{AI_COSTS, Setup, TClient, TokioRig, runtime};

type Run = (Vec<(u64, Purpose)>, Vec<(u64, LinkEvent)>, u64);

/// Strict, one contact (a send and a receive link), every link living 60 s, 15 minutes of virtual time over the tokio
/// driver: the run log's connects and events, and the end.
fn reconnecting_run() -> Run {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000)],
            pool: false,
            seed: 191,
        };
        let params = Params {
            phase_max_ms: 0,
            lifetime_ms: (60_000, 60_000),
            ..Params::default()
        };
        let x = TClient::new(&setup, sc.mode, params, sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let end = rig.setup.now().saturating_add(900_000);
        rig.x.run_until(end).await;
        let log = rig.x.driver.log().unwrap();
        (
            log.connects.iter().map(|(t, p, _)| (*t, *p)).collect(),
            log.events.clone(),
            end,
        )
    })
}

/// SC-04 `logical_link_id_in_events` (FIN5b-1). (a) The swap: links A (logical 0) and B (logical 1) are torn down at 0 and
/// 1 000 ms; B reconnects at 1 050, A at 1 500. Every teardown has *a* connect within the bound + 1 s — the pooled matching
/// of M6 (one logical id for all) passes — but A's own reconnect is 1 500 ms after its teardown: matched per logical link
/// the oracle rejects. (b) A run whose links reconnect every minute: each connection's `Up`/`TornDown` carry the logical id
/// its connect named, every logical link has several connections under one id, and the oracle passes per link.
#[test]
fn logical_link_id_in_events() {
    let events = [oracle_down(0, 1, 0), oracle_down(1_000, 2, 1)];
    let swapped = [oracle_connect(1_050, 3, 1), oracle_connect(1_500, 4, 0)];
    let e = check_reconnects(&events, &swapped, ORACLE_END, oracle_bound).unwrap_err();
    assert!(e.contains("1500 ms"), "{e}");
    let own = [oracle_connect(1_050, 3, 0), oracle_connect(1_500, 4, 1)];
    assert_eq!(
        check_reconnects(&events, &own, ORACLE_END, oracle_bound),
        Ok(2)
    );
    let pooled_events = [oracle_down(0, 1, 9), oracle_down(1_000, 2, 9)];
    let pooled = [oracle_connect(1_050, 3, 9), oracle_connect(1_500, 4, 9)];
    assert_eq!(
        check_reconnects(&pooled_events, &pooled, ORACLE_END, oracle_bound),
        Ok(2),
        "inside the pooled bound"
    );

    let (connects, events, end) = reconnecting_run();
    let mut logical_of: BTreeMap<LinkId, LogicalLinkId> = BTreeMap::new();
    let mut per_link: BTreeMap<LogicalLinkId, BTreeSet<LinkId>> = BTreeMap::new();
    for (_, p) in &connects {
        if let Purpose::Link(l, g) = p {
            assert!(
                logical_of.insert(*l, *g).is_none(),
                "one connect per connection"
            );
            per_link.entry(*g).or_default().insert(*l);
        }
    }
    for (t, e) in &events {
        let (LinkEvent::Up(l, g) | LinkEvent::TornDown(l, g, _)) = e else {
            continue;
        };
        assert_eq!(logical_of.get(l), Some(g), "{e:?} at {t}");
    }
    let checked = check_reconnects(&events, &connects, end, |why| {
        (why == Reason::Lifetime).then_some(180_000)
    });
    let text = format!(
        "connections per logical link: {per_link:?}; lifetime teardowns checked per logical link: {checked:?}"
    );
    evidence("SC-04", &text);
    assert_eq!(per_link.len(), 2, "{text}");
    assert!(per_link.values().all(|c| c.len() >= 3), "{text}");
    assert!(checked.is_ok_and(|n| n >= 4), "{text}");
}
