// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 follow-ups of the M5 review (G-01, G-07 `h01_…`, G-11; `docs/reviews/M05-review.md` §C/§H).

use secmp_crypto::{ConstantTimeEq, SecretBytes};
use secmp_proto::Encode;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{CellrContext, Response, ResponseCmd};
use secmp_relay::budget::QUEUE_RESERVATION;
use secmp_testkit::harness::{Harness, HarnessConfig};
use secmp_transport::{Error, QueueTransport, RelayQueueTransport, SendCap};

use crate::fixture::scripted;
use crate::scenarios::pair;
use crate::scripted::cell;

fn ok_send(seq: u32, cell_id: u64, evicted: Option<u64>) -> Response {
    Response {
        cmd_seq: seq,
        cmd: ResponseCmd::OkSend { cell_id, evicted },
    }
}

fn send_cap() -> SendCap {
    SendCap::from_route([1; 16], &SecretBytes::from_slice(&[9; 32]).unwrap()).unwrap()
}

fn try_send<S: std::io::Read + std::io::Write>(
    t: &mut RelayQueueTransport<S>,
) -> Result<(), Error> {
    t.send(&send_cap(), &cell(1)).map(|_| ())
}

/// G-01 (M05 review F-4, R-122): an `OK_SEND` whose evicted id lies outside `1…cell_id − 1` is a LINK-level rejection.
#[test]
fn ok_send_with_implausible_evicted_id_is_rejected() {
    // present = 1 with id 0, the id of the cell just stored, an id above it
    for evicted in [Some(0_u64), Some(10), Some(11)] {
        let (mut t, _relay, _id) = scripted(Box::new(move |req, _| {
            vec![ok_send(req.cmd_seq, 10, evicted)]
        }));
        assert_eq!(
            try_send(&mut t),
            Err(Error::Rejected),
            "evicted {evicted:?}"
        );
        assert!(t.is_closed(), "evicted {evicted:?}: the link is closed");
        assert_eq!(t.ping().err(), Some(Error::Closed));
    }
    // present = 0 with an id ≠ 0 is not a state of D.2: the decoder refuses it, so no transport ever sees it
    let mut padded = ok_send(1, 10, Some(3)).encode().unwrap().to_vec();
    assert_eq!(padded.get(13), Some(&1), "evicted_present sits at byte 13");
    *padded.get_mut(13).unwrap() = 0;
    assert!(
        Response::decode(&padded, CellrContext::Fetch).is_err(),
        "(0, 3) is refused by the decoder"
    );
    // the plausible ones
    for evicted in [Some(1_u64), Some(9), None] {
        let (mut t, _relay, _id) = scripted(Box::new(move |req, _| {
            vec![ok_send(req.cmd_seq, 10, evicted)]
        }));
        let out = t.send(&send_cap(), &cell(1)).unwrap();
        assert_eq!((out.cell_id, out.evicted), (10, evicted));
        assert!(!t.is_closed());
    }
}

/// G-07 (M05 review R-135): an identical `QUEUE_NEW` of an existing queue is answered `OK_QUEUE_NEW` with the same ids —
/// also at the memory limit — and a different one is refused `ERR_FULL`.
#[test]
fn h01_identical_queue_new_answers_ok() {
    let mut config = HarnessConfig::default();
    config.limits.budget.queue_bytes = Some(QUEUE_RESERVATION * 2);
    let mut h = Harness::new(config);
    let ca = h.add_client();
    h.connect(ca).unwrap();
    let token = h.access_key();
    let seeds: Vec<(SecretBytes<32>, SecretBytes<32>)> = (0..3)
        .map(|_| (h.client(ca).seed(), h.client(ca).seed()))
        .collect();
    let (t, _) = h.client(ca).link().unwrap();
    let [first, second, third] = seeds.as_slice() else {
        unreachable!()
    };
    let (r0, s0) = t.create_queue(&first.0, &first.1, &token).unwrap();
    t.create_queue(&second.0, &second.1, &token).unwrap();
    // at the limit now: the identical request is still answered, with the same capabilities
    let (r0b, s0b) = t.create_queue(&first.0, &first.1, &token).unwrap();
    assert!(bool::from(r0.ct_eq(&r0b) & s0.ct_eq(&s0b)), "the same ids");
    assert_eq!(r0.queue(), r0b.queue());
    assert_eq!(s0.sid(), s0b.sid());
    // a new queue is refused
    assert_eq!(
        t.create_queue(&third.0, &third.1, &token).err(),
        Some(Error::Full)
    );
}

/// The `sid` of the queue with this `rid` at the relay.
fn held_sid(h: &Harness, rid: [u8; 16]) -> [u8; 16] {
    h.relay()
        .snapshot_kat()
        .queues
        .iter()
        .find(|q| q.rid == rid)
        .map(|q| q.sid)
        .unwrap()
}

/// G-11 (VD-M5-FIX; mutants of `convo.rs`): after a queue is re-created the harness side's `set_send_cap` and
/// `set_recv_cap` take effect — the next `SEND` goes to the new queue, the next `FETCH` reads the new one.
#[test]
fn harness_cap_setters_take_effect() {
    let mut p = pair(HarnessConfig::default());
    let (ca, cb) = (p.a, p.b);
    let (a_new_recv, a_new_send) = p.h.create_queues(ca, 1).unwrap().pop().unwrap();
    let (b_new_recv, b_new_send) = p.h.create_queues(cb, 1).unwrap().pop().unwrap();
    let (a_new_rid, b_new_sid) = (*a_new_recv.queue().rid(), *b_new_send.sid());
    // A now sends to B's new queue and reads its own new one; B the mirror image
    p.side_a.set_send_cap(b_new_send);
    p.side_a.set_recv_cap(a_new_recv);
    p.side_b.set_send_cap(a_new_send);
    p.side_b.set_recv_cap(b_new_recv);
    let held = |h: &Harness, sid: [u8; 16]| -> usize {
        h.relay()
            .snapshot_kat()
            .queues
            .iter()
            .find(|q| q.sid == sid)
            .map_or(0, |q| q.cell_ids.len())
    };
    assert_eq!(held(&p.h, b_new_sid), 0);
    {
        let (t, e) = p.h.client(ca).link().unwrap();
        p.side_a.send_text(t, e, b"to the new queue").unwrap();
    }
    assert_eq!(held(&p.h, b_new_sid), 1, "the SEND used the new sid");
    // B reads its new queue (the new rid)
    {
        let (t, e) = p.h.client(cb).link().unwrap();
        let polled = p.side_b.poll(t, e).unwrap();
        assert_eq!(polled.delivered, 1, "the FETCH used the new rid");
    }
    assert_eq!(
        p.side_b.received().first().map(Vec::as_slice),
        Some(b"to the new queue".as_slice())
    );
    // and the other way: B answers into A's new queue, A reads it from there
    {
        let (t, e) = p.h.client(cb).link().unwrap();
        p.side_b.send_text(t, e, b"back").unwrap();
    }
    let into_a = held_sid(&p.h, a_new_rid);
    assert_eq!(held(&p.h, into_a), 1);
    {
        let (t, e) = p.h.client(ca).link().unwrap();
        assert_eq!(p.side_a.poll(t, e).unwrap().delivered, 1);
    }
    assert_eq!(
        p.side_a.received().first().map(Vec::as_slice),
        Some(b"back".as_slice())
    );
    let _ = Cell::from_bytes(&[0; 4096]);
}

/// X-09 (OPEN-M6-11): the scheduler core is sans-IO — no `tokio` path in `scheduler/core/`; the driver (Phase B) lives
/// in `scheduler/run.rs`.
#[test]
fn scheduler_core_has_no_tokio() {
    let core = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../secmp-client-core/src/scheduler/core");
    let mut seen = 0;
    for entry in std::fs::read_dir(&core).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("tokio"), "{} names tokio", path.display());
        seen += 1;
    }
    assert!(seen >= 3);
    let manifest = std::fs::read_to_string(core.join("../../../Cargo.toml")).unwrap();
    assert!(!manifest.contains("tokio"), "no runtime crate in Phase A");
}
