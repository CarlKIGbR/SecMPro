// SPDX-License-Identifier: AGPL-3.0-or-later
//! Multi-frame messages (spec §9.2, §9.3, D.2): `LINK_PUT` (client → relay) and `LINKR` (relay → client) are the
//! only messages of three frames: the first frame carries the head fields and `blob[0..4160]`, then two `CONT`
//! frames of 4100 B (`idx` 1, then 2), which repeat the message's `cmd_seq`; the blob is 12360 B.
//!
//! The rules (ADR-048 (f)): while a message is pending only its next `CONT` (same `cmd_seq`, the next `idx`)
//! continues it, and **any other frame is a LINK-level rejection** (§8.5); with nothing pending a `CONT` is a
//! rejection, and a `CONT` is never exempt from that. Staleness of `cmd_seq` is a property of the executor, not of
//! the assembler: a stale `LINK_PUT` is still assembled from its two `CONT`s and answered after the third frame.
//!
//! [`step`] is the decision on its own (plain `Copy` types, proven by the Kani harness `kani_cont_assembly`);
//! [`LinkPutAssembler`] and [`LinkrAssembler`] add the data.

use secmp_crypto::Zeroizing;

use crate::keys::{Ed25519Pk, Ed25519Sig};
use crate::link::{Error, Result};
use crate::sizes::{BLOB_PART_LEN, CONT_DATA_LEN, HASH_LEN, LINK_BLOB_LEN};
use crate::wire::Id;
use crate::wire::frame::{Cont, ContIdx, Request, RequestCmd, Response, ResponseCmd};

/// Where frame 1, `CONT` 1 and `CONT` 2 put their bytes in the blob: 0, 4160, 8260 (total 12360).
pub const BLOB_OFFSETS: [usize; 3] = [
    0,
    BLOB_PART_LEN,
    BLOB_PART_LEN.saturating_add(CONT_DATA_LEN),
];

/// What an incoming frame is, for the purposes of continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// The first frame of a multi-frame message (`LINK_PUT`, `LINKR`).
    Start {
        /// Its `cmd_seq`.
        cmd_seq: u32,
    },
    /// A `CONT` frame; `idx` as received (the decoders only produce 1 and 2).
    Cont {
        /// Its `cmd_seq`.
        cmd_seq: u32,
        /// Its `idx`.
        idx: u8,
    },
    /// Any other frame.
    Other,
}

/// The assembly state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing pending.
    Idle,
    /// Frame 1 taken; `CONT` 1 of this `cmd_seq` is next.
    AwaitOne {
        /// The pending message's `cmd_seq`.
        cmd_seq: u32,
    },
    /// `CONT` 1 taken; `CONT` 2 is next.
    AwaitTwo {
        /// The pending message's `cmd_seq`.
        cmd_seq: u32,
    },
}

/// What a frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A single-frame message; nothing pending.
    Single,
    /// The first frame of a multi-frame message was taken.
    Began,
    /// `CONT` 1 was taken.
    Continued,
    /// `CONT` 2 was taken: the message is complete.
    Complete,
}

/// The transition: `None` is the LINK-level rejection.
#[must_use]
pub const fn step(state: State, input: Input) -> Option<(State, Step)> {
    match (state, input) {
        (State::Idle, Input::Other) => Some((State::Idle, Step::Single)),
        (State::Idle, Input::Start { cmd_seq }) => Some((State::AwaitOne { cmd_seq }, Step::Began)),
        (State::AwaitOne { cmd_seq }, Input::Cont { cmd_seq: s, idx: 1 }) if s == cmd_seq => {
            Some((State::AwaitTwo { cmd_seq }, Step::Continued))
        }
        (State::AwaitTwo { cmd_seq }, Input::Cont { cmd_seq: s, idx: 2 }) if s == cmd_seq => {
            Some((State::Idle, Step::Complete))
        }
        _ => None,
    }
}

const fn cont_idx(idx: ContIdx) -> u8 {
    match idx {
        ContIdx::One => 1,
        ContIdx::Two => 2,
    }
}

/// A complete `LINK_PUT` (spec §9.3): its head fields and the 12360-byte blob.
pub struct LinkPut {
    /// The message's `cmd_seq` (every frame repeats it).
    pub cmd_seq: u32,
    /// Link-data id.
    pub ld_id: Id,
    /// One-time link data.
    pub one_time: bool,
    /// Expiry hour bucket.
    pub expires_bucket: u32,
    /// Owner key.
    pub owner_pk: Ed25519Pk,
    /// Access token.
    pub token: [u8; HASH_LEN],
    /// Owner signature over the D.6 message (with `SHA-256(blob)`).
    pub sig: Ed25519Sig,
    /// The blob, 12360 B.
    pub blob: Zeroizing<Vec<u8>>,
}

/// What [`LinkPutAssembler::push`] made of a request frame.
pub enum Assembled {
    /// A single-frame request, to be executed.
    Single(Request),
    /// A `LINK_PUT` frame or its first `CONT` was taken; nothing to execute yet and nothing to answer.
    Pending,
    /// The third frame completed a `LINK_PUT`.
    Put(Box<LinkPut>),
}

struct PutHead {
    cmd_seq: u32,
    ld_id: Id,
    one_time: bool,
    expires_bucket: u32,
    owner_pk: Ed25519Pk,
    token: [u8; HASH_LEN],
    sig: Ed25519Sig,
}

/// The relay's request-direction assembler (one per link).
pub struct LinkPutAssembler {
    state: State,
    head: Option<PutHead>,
    blob: Zeroizing<Vec<u8>>,
}

impl Default for LinkPutAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkPutAssembler {
    /// Nothing pending.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            head: None,
            blob: Zeroizing::new(Vec::new()),
        }
    }

    /// Whether a `LINK_PUT` is pending.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// Take the next request frame.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any frame that does not fit the pending state (spec §8.5, ADR-048 (f)); the
    /// assembler is reset and the caller closes the link.
    pub fn push(&mut self, request: Request) -> Result<Assembled> {
        let input = match &request.cmd {
            RequestCmd::LinkPut { .. } => Input::Start {
                cmd_seq: request.cmd_seq,
            },
            RequestCmd::Cont(c) => Input::Cont {
                cmd_seq: request.cmd_seq,
                idx: cont_idx(c.idx),
            },
            _ => Input::Other,
        };
        let Some((next, taken)) = step(self.state, input) else {
            self.reset();
            return Err(Error::Rejected);
        };
        self.state = next;
        match (taken, request.cmd) {
            (Step::Single, cmd) => Ok(Assembled::Single(Request {
                cmd_seq: request.cmd_seq,
                cmd,
            })),
            (
                Step::Began,
                RequestCmd::LinkPut {
                    ld_id,
                    one_time,
                    expires_bucket,
                    owner_pk,
                    token,
                    sig,
                    blob_part,
                },
            ) => {
                self.blob = Zeroizing::new(Vec::with_capacity(LINK_BLOB_LEN));
                self.blob.extend_from_slice(blob_part.as_slice());
                self.head = Some(PutHead {
                    cmd_seq: request.cmd_seq,
                    ld_id,
                    one_time,
                    expires_bucket,
                    owner_pk,
                    token,
                    sig,
                });
                Ok(Assembled::Pending)
            }
            (Step::Continued, RequestCmd::Cont(c)) => {
                self.blob.extend_from_slice(c.data.as_slice());
                Ok(Assembled::Pending)
            }
            (Step::Complete, RequestCmd::Cont(c)) => {
                self.blob.extend_from_slice(c.data.as_slice());
                let head = self.head.take().ok_or(Error::Rejected)?;
                let blob = core::mem::replace(&mut self.blob, Zeroizing::new(Vec::new()));
                if blob.len() != LINK_BLOB_LEN {
                    self.reset();
                    return Err(Error::Rejected);
                }
                Ok(Assembled::Put(Box::new(LinkPut {
                    cmd_seq: head.cmd_seq,
                    ld_id: head.ld_id,
                    one_time: head.one_time,
                    expires_bucket: head.expires_bucket,
                    owner_pk: head.owner_pk,
                    token: head.token,
                    sig: head.sig,
                    blob,
                })))
            }
            _ => {
                self.reset();
                Err(Error::Rejected)
            }
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.head = None;
        self.blob = Zeroizing::new(Vec::new());
    }
}

/// A complete `LINKR` (spec §9.3): the flags and the 12360-byte blob (a dummy when `present` is false).
pub struct Linkr {
    /// The message's `cmd_seq`.
    pub cmd_seq: u32,
    /// The link data exists.
    pub present: bool,
    /// The link data was consumed.
    pub consumed: bool,
    /// The blob, 12360 B.
    pub blob: Zeroizing<Vec<u8>>,
}

/// What [`LinkrAssembler::push`] made of a response frame.
pub enum AssembledResponse {
    /// A single-frame response.
    Single(Response),
    /// The first or second frame of a `LINKR` was taken.
    Pending,
    /// The third frame completed a `LINKR`.
    Linkr(Box<Linkr>),
}

/// The client's response-direction assembler (one per awaited `LINK_GET`).
pub struct LinkrAssembler {
    state: State,
    head: Option<(u32, bool, bool)>,
    blob: Zeroizing<Vec<u8>>,
}

impl Default for LinkrAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkrAssembler {
    /// Nothing pending.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            head: None,
            blob: Zeroizing::new(Vec::new()),
        }
    }

    /// Take the next response frame.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any frame that does not fit the pending state; the client closes the link.
    pub fn push(&mut self, response: Response) -> Result<AssembledResponse> {
        let input = match &response.cmd {
            ResponseCmd::LinkR { .. } => Input::Start {
                cmd_seq: response.cmd_seq,
            },
            ResponseCmd::Cont(c) => Input::Cont {
                cmd_seq: response.cmd_seq,
                idx: cont_idx(c.idx),
            },
            _ => Input::Other,
        };
        let Some((next, taken)) = step(self.state, input) else {
            self.reset();
            return Err(Error::Rejected);
        };
        self.state = next;
        match (taken, response.cmd) {
            (Step::Single, cmd) => Ok(AssembledResponse::Single(Response {
                cmd_seq: response.cmd_seq,
                cmd,
            })),
            (
                Step::Began,
                ResponseCmd::LinkR {
                    present,
                    consumed,
                    blob_part,
                },
            ) => {
                self.blob = Zeroizing::new(Vec::with_capacity(LINK_BLOB_LEN));
                self.blob.extend_from_slice(blob_part.as_slice());
                self.head = Some((response.cmd_seq, present, consumed));
                Ok(AssembledResponse::Pending)
            }
            (Step::Continued, ResponseCmd::Cont(c)) => {
                self.blob.extend_from_slice(c.data.as_slice());
                Ok(AssembledResponse::Pending)
            }
            (Step::Complete, ResponseCmd::Cont(c)) => {
                self.blob.extend_from_slice(c.data.as_slice());
                let (cmd_seq, present, consumed) = self.head.take().ok_or(Error::Rejected)?;
                let blob = core::mem::replace(&mut self.blob, Zeroizing::new(Vec::new()));
                if blob.len() != LINK_BLOB_LEN {
                    self.reset();
                    return Err(Error::Rejected);
                }
                Ok(AssembledResponse::Linkr(Box::new(Linkr {
                    cmd_seq,
                    present,
                    consumed,
                    blob,
                })))
            }
            _ => {
                self.reset();
                Err(Error::Rejected)
            }
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.head = None;
        self.blob = Zeroizing::new(Vec::new());
    }
}

/// Split a 12360-byte blob into the parts the three frames carry (frame 1, `CONT` 1, `CONT` 2).
///
/// # Errors
/// [`Error::Rejected`] unless `blob` is exactly 12360 bytes.
pub fn split_blob(blob: &[u8]) -> Result<(Box<[u8; BLOB_PART_LEN]>, Cont, Cont)> {
    let (first, rest) = blob
        .split_first_chunk::<BLOB_PART_LEN>()
        .ok_or(Error::Rejected)?;
    let (one, rest) = rest
        .split_first_chunk::<CONT_DATA_LEN>()
        .ok_or(Error::Rejected)?;
    let (two, rest) = rest
        .split_first_chunk::<CONT_DATA_LEN>()
        .ok_or(Error::Rejected)?;
    if !rest.is_empty() {
        return Err(Error::Rejected);
    }
    Ok((
        Box::new(*first),
        Cont {
            idx: ContIdx::One,
            data: Box::new(*one),
        },
        Cont {
            idx: ContIdx::Two,
            data: Box::new(*two),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::testutil::{ed25519, sig};

    fn put(cmd_seq: u32, fill: u8) -> Result<Request> {
        Ok(Request {
            cmd_seq,
            cmd: RequestCmd::LinkPut {
                ld_id: [7; 16],
                one_time: true,
                expires_bucket: 99,
                owner_pk: ed25519(3)?,
                token: [4; 32],
                sig: sig(5)?,
                blob_part: Box::new([fill; BLOB_PART_LEN]),
            },
        })
    }

    fn cont(cmd_seq: u32, idx: ContIdx, fill: u8) -> Request {
        Request {
            cmd_seq,
            cmd: RequestCmd::Cont(Cont {
                idx,
                data: Box::new([fill; CONT_DATA_LEN]),
            }),
        }
    }

    fn ping(cmd_seq: u32) -> Request {
        Request {
            cmd_seq,
            cmd: RequestCmd::Ping,
        }
    }

    fn linkr(cmd_seq: u32, fill: u8) -> Response {
        Response {
            cmd_seq,
            cmd: ResponseCmd::LinkR {
                present: true,
                consumed: false,
                blob_part: Box::new([fill; BLOB_PART_LEN]),
            },
        }
    }

    fn rcont(cmd_seq: u32, idx: ContIdx, fill: u8) -> Response {
        Response {
            cmd_seq,
            cmd: ResponseCmd::Cont(Cont {
                idx,
                data: Box::new([fill; CONT_DATA_LEN]),
            }),
        }
    }

    /// The transition table of ADR-048 (f), written out: only the next `CONT` continues, anything else while a
    /// message is pending rejects, and so does a `CONT` with nothing pending.
    #[test]
    fn step_follows_the_table() {
        let states = [
            State::Idle,
            State::AwaitOne { cmd_seq: 1 },
            State::AwaitTwo { cmd_seq: 1 },
        ];
        let mut inputs = vec![
            Input::Other,
            Input::Start { cmd_seq: 1 },
            Input::Start { cmd_seq: 2 },
        ];
        for cmd_seq in [1, 2] {
            for idx in 0..=3 {
                inputs.push(Input::Cont { cmd_seq, idx });
            }
        }
        for state in states {
            for input in &inputs {
                let want = match (state, *input) {
                    (State::Idle, Input::Other) => Some((State::Idle, Step::Single)),
                    (State::Idle, Input::Start { cmd_seq }) => {
                        Some((State::AwaitOne { cmd_seq }, Step::Began))
                    }
                    (State::AwaitOne { cmd_seq: 1 }, Input::Cont { cmd_seq: 1, idx: 1 }) => {
                        Some((State::AwaitTwo { cmd_seq: 1 }, Step::Continued))
                    }
                    (State::AwaitTwo { cmd_seq: 1 }, Input::Cont { cmd_seq: 1, idx: 2 }) => {
                        Some((State::Idle, Step::Complete))
                    }
                    _ => None,
                };
                assert_eq!(step(state, *input), want, "{state:?} {input:?}");
            }
        }
    }

    #[test]
    fn blob_offsets_and_cont_indices() {
        assert_eq!(BLOB_OFFSETS, [0, 4160, 8260]);
        assert_eq!(
            BLOB_PART_LEN.saturating_add(CONT_DATA_LEN.saturating_mul(2)),
            LINK_BLOB_LEN,
            "three frames carry the whole blob"
        );
        assert_eq!(cont_idx(ContIdx::One), 1);
        assert_eq!(cont_idx(ContIdx::Two), 2);
    }

    #[test]
    fn link_put_assembles_in_order() -> Result<()> {
        let mut a = LinkPutAssembler::new();
        assert!(!a.is_pending());
        assert!(matches!(a.push(put(5, 0xa1)?)?, Assembled::Pending));
        assert!(a.is_pending());
        assert!(matches!(
            a.push(cont(5, ContIdx::One, 0xb2))?,
            Assembled::Pending
        ));
        assert!(a.is_pending());
        let Assembled::Put(p) = a.push(cont(5, ContIdx::Two, 0xc3))? else {
            return Err(Error::Rejected);
        };
        assert!(!a.is_pending());
        assert_eq!(
            (p.cmd_seq, p.ld_id, p.one_time, p.expires_bucket, p.token),
            (5, [7; 16], true, 99, [4; 32])
        );
        assert_eq!(p.blob.len(), LINK_BLOB_LEN);
        let at = |i: usize| p.blob.get(i).copied();
        let [o0, o1, o2] = BLOB_OFFSETS;
        assert_eq!(at(o0), Some(0xa1));
        assert_eq!(at(o1.saturating_sub(1)), Some(0xa1));
        assert_eq!(at(o1), Some(0xb2));
        assert_eq!(at(o2.saturating_sub(1)), Some(0xb2));
        assert_eq!(at(o2), Some(0xc3));
        assert_eq!(at(LINK_BLOB_LEN.saturating_sub(1)), Some(0xc3));
        // the assembler is reusable, and a single-frame command passes through unchanged
        let Assembled::Single(r) = a.push(ping(9))? else {
            return Err(Error::Rejected);
        };
        assert_eq!((r.cmd_seq, r.cmd), (9, RequestCmd::Ping));
        Ok(())
    }

    #[test]
    fn link_put_rejects_every_other_order() -> Result<()> {
        type Frames = fn() -> Result<Vec<Request>>;
        let cases: [(&str, Frames); 7] = [
            ("orphan CONT 1", || Ok(vec![cont(5, ContIdx::One, 0)])),
            ("orphan CONT 2", || Ok(vec![cont(5, ContIdx::Two, 0)])),
            ("CONT 2 first", || {
                Ok(vec![put(5, 0)?, cont(5, ContIdx::Two, 0)])
            }),
            ("CONT 1 twice", || {
                Ok(vec![
                    put(5, 0)?,
                    cont(5, ContIdx::One, 0),
                    cont(5, ContIdx::One, 0),
                ])
            }),
            ("another cmd_seq", || {
                Ok(vec![put(5, 0)?, cont(6, ContIdx::One, 0)])
            }),
            ("PING between", || Ok(vec![put(5, 0)?, ping(6)])),
            ("LINK_PUT inside a LINK_PUT", || {
                Ok(vec![put(5, 0)?, put(5, 0)?])
            }),
        ];
        for (what, frames) in cases {
            let mut a = LinkPutAssembler::new();
            let mut verdict = Ok(());
            for f in frames()? {
                if let Err(e) = a.push(f) {
                    verdict = Err(e);
                    break;
                }
            }
            assert_eq!(verdict, Err(Error::Rejected), "{what}");
            // a rejection resets the assembler
            assert!(!a.is_pending(), "{what}: reset");
            assert!(matches!(a.push(ping(1))?, Assembled::Single(_)), "{what}");
        }
        Ok(())
    }

    #[test]
    fn linkr_assembles_in_order_and_rejects_the_rest() -> Result<()> {
        let mut a = LinkrAssembler::new();
        assert!(matches!(
            a.push(linkr(3, 1)),
            Ok(AssembledResponse::Pending)
        ));
        assert!(matches!(
            a.push(rcont(3, ContIdx::One, 2)),
            Ok(AssembledResponse::Pending)
        ));
        let Ok(AssembledResponse::Linkr(l)) = a.push(rcont(3, ContIdx::Two, 3)) else {
            return Err(Error::Rejected);
        };
        assert_eq!((l.cmd_seq, l.present, l.consumed), (3, true, false));
        assert_eq!(l.blob.len(), LINK_BLOB_LEN);
        let at = |i: usize| l.blob.get(i).copied();
        let [o0, o1, o2] = BLOB_OFFSETS;
        assert_eq!((at(o0), at(o1), at(o2)), (Some(1), Some(2), Some(3)));
        let ok = Response {
            cmd_seq: 4,
            cmd: ResponseCmd::Ok,
        };
        assert!(matches!(a.push(ok), Ok(AssembledResponse::Single(_))));
        // orphan CONT, wrong order, wrong cmd_seq, a single frame inside a LINKR
        for frames in [
            vec![rcont(3, ContIdx::One, 0)],
            vec![linkr(3, 0), rcont(3, ContIdx::Two, 0)],
            vec![linkr(3, 0), rcont(4, ContIdx::One, 0)],
            vec![linkr(3, 0), rcont(3, ContIdx::One, 0), linkr(3, 0)],
            vec![
                linkr(3, 0),
                Response {
                    cmd_seq: 3,
                    cmd: ResponseCmd::Ok,
                },
            ],
        ] {
            let mut a = LinkrAssembler::new();
            let verdict = frames.into_iter().try_for_each(|f| a.push(f).map(|_| ()));
            assert_eq!(verdict, Err(Error::Rejected));
            let ok = Response {
                cmd_seq: 1,
                cmd: ResponseCmd::Ok,
            };
            assert!(matches!(a.push(ok), Ok(AssembledResponse::Single(_))));
        }
        Ok(())
    }

    #[test]
    fn split_blob_cuts_at_the_offsets() -> Result<()> {
        let blob: Vec<u8> = (0..LINK_BLOB_LEN)
            .map(|i| u8::try_from(i.rem_euclid(251)).unwrap_or(0))
            .collect();
        let (first, one, two) = split_blob(&blob)?;
        let [_, o1, o2] = BLOB_OFFSETS;
        assert_eq!(first.as_slice(), blob.get(..o1).unwrap_or_default());
        assert_eq!(one.data.as_slice(), blob.get(o1..o2).unwrap_or_default());
        assert_eq!(two.data.as_slice(), blob.get(o2..).unwrap_or_default());
        assert_eq!((one.idx, two.idx), (ContIdx::One, ContIdx::Two));
        let shorter = blob
            .get(..LINK_BLOB_LEN.saturating_sub(1))
            .unwrap_or_default();
        assert_eq!(split_blob(shorter).err(), Some(Error::Rejected));
        let longer = [blob.as_slice(), &[0]].concat();
        assert_eq!(split_blob(&longer).err(), Some(Error::Rejected));
        Ok(())
    }
}
