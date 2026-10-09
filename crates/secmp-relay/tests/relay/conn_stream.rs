// SPDX-License-Identifier: AGPL-3.0-or-later
//! The connection over a byte stream (D.1, `docs/07:106` "over an abstract byte stream"): records and frames arrive
//! split at any byte or coalesced in one write, and the relay answers each one exactly when it is complete — the
//! same bytes in every case. Extra tests of M5 Phase B (not TEST-SPEC rows; the harness row H-11 is Phase C).

use secmp_proto::link::client;
use secmp_relay::{Connection, Limits};

use crate::fixture::{Client, FRAME, RelayFx, client_entropy, now, relay_hs_entropy};

/// Feed `bytes` in pieces of `chunk` (0: all at once) and collect what the relay wrote, per piece.
fn feed(conn: &mut Connection<'_>, bytes: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let pieces: Vec<&[u8]> = if chunk == 0 {
        vec![bytes]
    } else {
        bytes.chunks(chunk).collect()
    };
    for p in pieces {
        let o = conn.on_bytes(p, now(), &mut relay_hs_entropy());
        assert!(!o.close, "the connection stays open");
        out.push(o.bytes);
    }
    out
}

/// One handshake and one `PING` with every write split into `chunk`-byte pieces (0: unsplit): the relay's bytes,
/// and whether every answer came with the piece that completed its record or frame.
fn run(chunk: usize) -> (Vec<u8>, bool) {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::vectors());
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let access = fx.access();
    let (hello, st) = client::start(fx.relay_fp, Some(&access), now().unix_secs).unwrap();
    let info = feed(&mut conn, &hello, chunk);
    let (last, before) = info.split_last().unwrap();
    let mut on_time = before.iter().all(Vec::is_empty) && !last.is_empty();
    let (hs1, wait) = st.on_relayinfo(last, &mut client_entropy()).unwrap();
    let hs2_pieces = feed(&mut conn, &hs1, chunk);
    let (hs2, before) = hs2_pieces.split_last().unwrap();
    on_time &= before.iter().all(Vec::is_empty) && !hs2.is_empty();
    let mut client = Client::new(wait.on_hs2(hs2).unwrap(), access);
    let frame = client.seal(&Client::ping(1));
    let resp_pieces = feed(&mut conn, &frame, chunk);
    let (resp, before) = resp_pieces.split_last().unwrap();
    on_time &= before.iter().all(Vec::is_empty) && resp.len() == FRAME;
    client.open(resp, secmp_proto::wire::frame::CellrContext::Fetch);
    ([last.clone(), hs2.clone(), resp.clone()].concat(), on_time)
}

/// Every record and frame split into pieces of 1, 2, 7, 1000 and 4351 bytes gives the bytes of the unsplit run,
/// each answer exactly with the piece that completes its input.
#[test]
fn connection_answers_each_record_when_complete_at_any_split() {
    let (whole, on_time) = run(0);
    assert!(on_time);
    for chunk in [1, 2, 7, 1000, 4351] {
        let (bytes, on_time) = run(chunk);
        assert!(
            on_time,
            "chunk {chunk}: an answer before its input was complete"
        );
        assert_eq!(bytes, whole, "chunk {chunk}: the same bytes");
    }
}

/// `HS1` and the first frame in one write: `HS2` and the frame's answer come back together, in order; `HELLO` and
/// the bytes after it in one write: `RELAYINFO`, and the rest is kept for `HS1`.
#[test]
fn connection_takes_coalesced_records_and_frames() {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::vectors());
    let access = fx.access();
    // reference run, one record per write
    let (expected, _) = run(0);
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let (hello, st) = client::start(fx.relay_fp, Some(&access), now().unix_secs).unwrap();
    let info = conn.on_bytes(&hello, now(), &mut relay_hs_entropy());
    let (hs1, wait) = st.on_relayinfo(&info.bytes, &mut client_entropy()).unwrap();
    // the client cannot seal its first frame before HS2; replay the reference link's frame 0 instead: the
    // same keys (the same draws), so the same frame
    let mut probe = Connection::accept(&relay, now()).unwrap();
    let _ = probe.on_bytes(&hello, now(), &mut relay_hs_entropy());
    let hs2 = probe.on_bytes(&hs1, now(), &mut relay_hs_entropy());
    let mut client = Client::new(wait.on_hs2(&hs2.bytes).unwrap(), access);
    let frame = client.seal(&Client::ping(1));
    let out = conn.on_bytes(&[hs1, frame].concat(), now(), &mut relay_hs_entropy());
    assert!(!out.close);
    assert_eq!(
        [info.bytes, out.bytes].concat(),
        expected,
        "RELAYINFO, then HS2 and the PING answer in one write"
    );
    // HELLO with the first byte of HS1 behind it: RELAYINFO only, the byte is kept
    let mut conn = Connection::accept(&relay, now()).unwrap();
    let (hello, _) = client::start(fx.relay_fp, None, now().unix_secs).unwrap();
    let out = conn.on_bytes(
        &[&hello[..], &[0x0b]].concat(),
        now(),
        &mut relay_hs_entropy(),
    );
    assert!(!out.close);
    assert_eq!(out.bytes.len(), 1744, "RELAYINFO");
    assert!(!conn.is_closed() && conn.executor().is_none());
}
