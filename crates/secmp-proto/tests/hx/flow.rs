// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-INV/HX end to end with OS randomness (TEST-SPEC-M4 (a) `hx_roundtrip_os_rng`).

use crate::fixture::{Inviter, invitee_run};
use secmp_proto::Encode;
use secmp_proto::hx::Responder;
use secmp_proto::prekeys::PrekeyStore;
use secmp_proto::tr::OsEntropy;

#[test]
fn hx_roundtrip_os_rng() {
    let mut rng = OsEntropy;
    let mut inviter = Inviter::new(&mut rng);
    let guest = invitee_run(&inviter, &mut rng);
    let record_opk = inviter.record().opk_id;
    assert!(inviter.store.opk(record_opk).is_some());
    let record = inviter.record().duplicate_kat().unwrap();
    let mut store = std::mem::take(&mut inviter.store);
    let accepted = Responder::accept(
        &guest.cells,
        &record,
        &mut store,
        &inviter.identity.responder_keys(),
        &mut rng,
    )
    .unwrap();
    assert!(store.opk(record_opk).is_none(), "OPK deleted on success");
    assert_eq!(
        accepted.peer.encode().unwrap(),
        guest.identity.public().encode().unwrap()
    );
    assert_eq!(accepted.profile.name(), "alice");
    assert_eq!(accepted.routes.len(), 1);
}
