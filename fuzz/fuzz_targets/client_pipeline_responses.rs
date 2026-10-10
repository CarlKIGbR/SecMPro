// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-01 `client_pipeline_responses` (M6 Phase A; TEST-SPEC-M6 (j)): outstanding requests of a pipelined client channel
//! (`secmp_transport::Channel`) and arbitrary response plaintexts sealed honestly by the relay's end of the link.
//!
//! Input: a count byte (1 + modulo 4 requests) and four kind bytes (modulo 4: `PING`, `SEND`, `FETCH`, `FETCH_MULTI`),
//! then up to 8 units, each a `u16` length (modulo 4336, cut to 4335) and that many bytes — the plaintext the relay seals
//! into the next response frame: 5 + 8 × (2 + 4335) = 34 701 bytes.
//!
//! Invariants: no panic; an `Err` is the uniform `Rejected` and closes the channel (every later call is `Closed`); for
//! the single-frame kinds (`PING`, `SEND`) a unit completes the request exactly when its plaintext decodes as a D.2
//! response with the request's `cmd_seq` that fits the request (an independent restatement of the rule) — any other
//! unit is `Rejected`; a `FETCH`/`FETCH_MULTI` completes only after 1 (`ERR`) or 4 / 8 frames.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::SecretBytes;
use secmp_proto::codec::pad;
use secmp_proto::sizes::FRAME_PLAINTEXT_LEN;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{CellrContext, ErrCode, Response, ResponseCmd};
use secmp_transport::{Channel, Command, Error, Outcome, RecvCap, SendCap};

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{Bytes, Fixture};

const MAX_UNITS: usize = 8;

fn fits_single(kind: u8, response: &Response, seq: u32) -> bool {
    if response.cmd_seq != seq {
        return false;
    }
    match (kind, &response.cmd) {
        (0, ResponseCmd::Ok) => true,
        (0, ResponseCmd::Err(c)) | (1, ResponseCmd::Err(c)) => {
            matches!(c, ErrCode::Malformed | ErrCode::Rate)
                || (kind == 1 && matches!(c, ErrCode::NoQueue | ErrCode::Auth))
        }
        (1, ResponseCmd::OkSend { cell_id, evicted }) => {
            *cell_id != 0 && evicted.is_none_or(|e| e >= 1 && e < *cell_id)
        }
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes(data);
    let count = 1 + usize::from(b.u8() % 4);
    let kinds: Vec<u8> = (0..4).map(|_| b.u8() % 4).collect();
    let (client_link, mut relay_link) = Fixture::get().honest_links();
    let mut chan = Channel::from_link_kat(client_link);
    let recv = RecvCap::from_seed(&SecretBytes::from_slice(&[0x31; 32]).unwrap()).unwrap();
    let send = SendCap::from_route([0x32; 16], &SecretBytes::from_slice(&[0x33; 32]).unwrap()).unwrap();
    let cell = Cell::from_bytes(&[0x34; 4096]).unwrap();
    // the outstanding requests: (kind, cmd_seq, frames fed so far)
    let mut outstanding: Vec<(u8, u32, usize)> = Vec::new();
    for kind in kinds.iter().take(count) {
        let entries = [(&recv, 0_u64)];
        let command = match kind {
            0 => Command::Ping,
            1 => Command::Send { to: &send, cell: &cell },
            2 => Command::Fetch { from: &recv, ack: 0 },
            _ => Command::FetchMulti { from: &entries },
        };
        let prepared = chan.prepare(&command).unwrap();
        chan.begin_write(&prepared).unwrap();
        outstanding.push((*kind, prepared.seq(), 0));
    }
    for _ in 0..MAX_UNITS {
        if b.0.is_empty() {
            break;
        }
        let len = usize::from(b.u16()) % 4336;
        let payload = b.take(len.min(FRAME_PLAINTEXT_LEN - 1));
        let unit = relay_link.seal(&payload).unwrap();
        if chan.is_closed() {
            assert_eq!(chan.accept(&unit[..]).err(), Some(Error::Closed));
            continue;
        }
        let Some(front) = outstanding.first().copied() else {
            // nothing outstanding: an unsolicited frame is a rejection
            assert_eq!(chan.accept(&unit[..]).err(), Some(Error::Rejected));
            assert!(chan.is_closed());
            continue;
        };
        let (kind, seq, fed) = front;
        let context = if kind == 3 { CellrContext::FetchMulti } else { CellrContext::Fetch };
        let padded = pad(&payload, FRAME_PLAINTEXT_LEN).unwrap();
        let decoded = Response::decode(&padded, context).ok();
        let result = chan.accept(&unit[..]);
        match result {
            Err(e) => {
                assert_eq!(e, Error::Rejected);
                assert!(chan.is_closed());
            }
            Ok(None) => {
                // only a multi-frame answer may be pending, and only after a valid first frame
                assert!(kind >= 2, "a single-frame request stayed pending");
                if let Some(first) = outstanding.first_mut() {
                    first.2 += 1;
                }
            }
            Ok(Some(done)) => {
                assert_eq!(done.seq, seq);
                let response = decoded.as_ref().expect("a completion needs a decodable frame");
                assert_eq!(response.cmd_seq, seq);
                match (kind, &done.outcome) {
                    (0, Outcome::Ping(_)) | (1, Outcome::Send(_)) => {
                        assert!(fits_single(kind, response, seq));
                    }
                    (2, Outcome::Fetch(_)) => {
                        let frames = fed + 1;
                        assert!(
                            frames == 1 && matches!(response.cmd, ResponseCmd::Err(_)) || frames == 4,
                            "FETCH completed after {frames} frames"
                        );
                    }
                    (3, Outcome::FetchMulti(_)) => {
                        let frames = fed + 1;
                        assert!(
                            frames == 1 && matches!(response.cmd, ResponseCmd::Err(_)) || frames == 8,
                            "FETCH_MULTI completed after {frames} frames"
                        );
                    }
                    _ => panic!("the outcome is not the request's"),
                }
                outstanding.remove(0);
            }
        }
        if matches!(kind, 0 | 1) && chan.is_closed() {
            // a misfit closed the channel: the oracle agrees that the unit did not fit
            assert!(decoded.as_ref().is_none_or(|r| !fits_single(kind, r, seq)));
        }
    }
});
