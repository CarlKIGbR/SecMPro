// SPDX-License-Identifier: AGPL-3.0-or-later
//! The frame rate across the three frames of a `LINK_PUT` (spec §9.7 item 7, ADR-048 (p); the relay's reading,
//! `crates/secmp-relay/src/executor.rs`): every request frame takes a token; a `LINK_PUT` one of whose frames finds
//! the bucket empty is answered with one ERR 7 after its third frame, unless its `cmd_seq` is stale — then ERR 6
//! (the stale rule comes first). Extra tests of M5 Phase B (not TEST-SPEC rows; RL-13 covers the first frame).

use secmp_proto::wire::frame::{ErrCode, ResponseCmd};
use secmp_relay::rate::RateLimit;
use secmp_relay::{Limits, Now};

use crate::fixture::{Answer, Bench, EXPIRES, Key, Put, lots};

const fn at(mono_ms: u64) -> Now {
    Now {
        unix_secs: crate::fixture::NOW,
        mono_ms,
    }
}

/// A relay with one token per link, refilled once a second.
fn bench() -> Bench {
    Bench::new(Limits {
        link_rate: Some(RateLimit {
            burst: 1,
            per_sec: 1,
        }),
        ..Limits::vectors()
    })
}

/// Run the three frames of a `LINK_PUT` with `cmd_seq` at the given monotonic times; the answer after frame 3.
fn put(b: &mut Bench, cmd_seq: u32, times: [u64; 3], ld: u8) -> ResponseCmd {
    let owner = Key::of(0x51);
    let blob = vec![ld; 12_360];
    let ld_id = [ld; 16];
    let frames = b.client.link_put(
        cmd_seq,
        &Put {
            ld_id: &ld_id,
            one_time: true,
            expires_bucket: EXPIRES,
            owner: &owner,
            blob: &blob,
        },
    );
    let mut last = None;
    for (i, (req, t)) in frames.iter().zip(times).enumerate() {
        let answer = b.run(req, at(t), &mut lots());
        if i < 2 {
            assert!(answer.is_pending(), "nothing after frame {}", i.saturating_add(1));
        } else {
            last = Some(answer);
        }
    }
    let frames = last.map(Answer::frames).unwrap();
    assert_eq!(frames.len(), 1, "one answer after frame 3");
    frames.into_iter().next().unwrap().cmd
}

fn is_err(cmd: &ResponseCmd, code: ErrCode) -> bool {
    matches!(cmd, ResponseCmd::Err(c) if *c == code)
}

/// Frame 1 takes the only token, `CONT` 1 finds the bucket empty, `CONT` 2 comes a second later with a fresh
/// token: the `LINK_PUT` is over the rate (ERR 7) and nothing is stored; the same `LINK_PUT` paced at one frame a
/// second is stored.
#[test]
fn a_link_put_with_one_frame_over_the_rate_is_err_7() {
    let mut b = bench();
    let before = b.digest();
    let cmd = put(&mut b, 1, [0, 0, 1000], 1);
    assert!(is_err(&cmd, ErrCode::Rate), "ERR 7");
    assert_eq!(b.digest(), before, "nothing stored");
    assert_eq!(b.link_post().2, 1, "cmd_seq recorded");
    let cmd = put(&mut b, 2, [2000, 3000, 4000], 2);
    assert!(matches!(cmd, ResponseCmd::Ok), "paced: stored");
}

/// A stale `LINK_PUT` whose `CONT` 1 is over the rate is answered ERR 6: the stale rule comes first.
#[test]
fn a_stale_link_put_over_the_rate_is_err_6() {
    let mut b = bench();
    let cmd = put(&mut b, 5, [0, 1000, 2000], 3);
    assert!(matches!(cmd, ResponseCmd::Ok));
    let cmd = put(&mut b, 5, [3000, 3000, 4000], 4);
    assert!(is_err(&cmd, ErrCode::Malformed), "ERR 6, not ERR 7");
}
