// SPDX-License-Identifier: AGPL-3.0-or-later
//! A scripted relay: a byte stream whose far end does the relay's side of SecMP-LINK with real keys and then answers
//! each request frame with whatever responses a closure says — correct ones, or malformed ones (T-09). It records
//! every request it opened (T-07, T-08).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::rc::Rc;

use secmp_crypto::{Ed25519SigningKey, MlKem1024Dk, SecretBytes, VectorStream, X25519Secret};
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::link::Link;
use secmp_proto::link::relay::{AwaitHs1, RelayKeys, accept_ring};
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN};
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{Cellr, ErrCode, Request, Response, ResponseCmd};
use secmp_testkit::harness::EntropyPool;

/// The unix time the scripted relay and its client agree on.
pub const T0: u64 = 1_760_000_000;
const HELLO_LEN: usize = 9;
const HS1_LEN: usize = 2856;

/// A closure from the n-th request (counting every frame, `CONT` included) to the responses to send back.
pub type Script = Box<dyn FnMut(&Request, usize) -> Vec<Response>>;

enum Phase {
    Hello,
    Hs1(Box<AwaitHs1<'static>>),
    Linked(Box<Link>),
}

struct Inner {
    ring: &'static [RelayKeys],
    phase: Option<Phase>,
    input: Vec<u8>,
    out: VecDeque<u8>,
    entropy: EntropyPool,
    script: Script,
    seen: Vec<Request>,
    sess_id: Option<[u8; 16]>,
}

/// The scripted relay's stream; clones share the relay.
#[derive(Clone)]
pub struct Scripted(Rc<RefCell<Inner>>);

/// The identity of the scripted relay.
pub struct Identity {
    pub fp: [u8; 32],
    pub access: SecretBytes<32>,
}

fn seeds() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut s = VectorStream::new("scripted-relay-keys", 0);
    (s.take(32), s.take(32), s.take(64), s.take(32))
}

fn keys() -> RelayKeys {
    let (sig, dh, kem, access) = seeds();
    RelayKeys::new(
        Ed25519SigningKey::from_seed(&sig).unwrap(),
        X25519Secret::from_bytes(&dh).unwrap(),
        MlKem1024Dk::from_seed(&kem).unwrap(),
        SecretBytes::from_slice(&access).unwrap(),
        1,
    )
    .unwrap()
}

/// The pinned fingerprint and the access key of the scripted relay.
pub fn identity() -> Identity {
    let (_, _, _, access) = seeds();
    Identity {
        fp: keys().fp(),
        access: SecretBytes::from_slice(&access).unwrap(),
    }
}

impl Scripted {
    /// A scripted relay that answers with `script`.
    pub fn new(script: Script) -> Self {
        let ring: &'static [RelayKeys] = Box::leak(vec![keys()].into_boxed_slice());
        Self(Rc::new(RefCell::new(Inner {
            ring,
            phase: Some(Phase::Hello),
            input: Vec::new(),
            out: VecDeque::new(),
            entropy: EntropyPool::new("scripted-relay", 0),
            script,
            seen: Vec::new(),
            sess_id: None,
        })))
    }

    /// The requests opened so far, in order.
    pub fn seen(&self) -> Vec<Request> {
        self.0.borrow().seen.clone()
    }

    /// The link's `sess_id`, once the handshake is done.
    pub fn sess_id(&self) -> [u8; 16] {
        self.0.borrow().sess_id.unwrap()
    }
}

impl Inner {
    fn step(&mut self) {
        loop {
            match self.phase.take() {
                Some(Phase::Hello) => {
                    if self.input.len() < HELLO_LEN {
                        self.phase = Some(Phase::Hello);
                        return;
                    }
                    let record: Vec<u8> = self.input.drain(..HELLO_LEN).collect();
                    let (info, st) = accept_ring(self.ring)
                        .on_hello(&record, T0 + 30 * 86_400)
                        .unwrap();
                    self.out.extend(info);
                    self.phase = Some(Phase::Hs1(Box::new(st)));
                }
                Some(Phase::Hs1(st)) => {
                    if self.input.len() < HS1_LEN {
                        self.phase = Some(Phase::Hs1(st));
                        return;
                    }
                    let record: Vec<u8> = self.input.drain(..HS1_LEN).collect();
                    let (hs2, link) = st.on_hs1(&record, self.entropy.get()).unwrap();
                    self.out.extend(hs2);
                    self.sess_id = Some(*link.sess_id());
                    self.phase = Some(Phase::Linked(Box::new(link)));
                }
                Some(Phase::Linked(mut link)) => {
                    if self.input.len() < FRAME_LEN {
                        self.phase = Some(Phase::Linked(link));
                        return;
                    }
                    let unit: Vec<u8> = self.input.drain(..FRAME_LEN).collect();
                    let request = link.open_request(&unit).unwrap();
                    let n = self.seen.len();
                    self.seen.push(request.clone());
                    for response in (self.script)(&request, n) {
                        let padded = response.encode().unwrap();
                        let payload = unpad(&padded, FRAME_PLAINTEXT_LEN).unwrap();
                        let frame = link.seal(payload).unwrap();
                        self.out.extend(frame.iter().copied());
                    }
                    self.phase = Some(Phase::Linked(link));
                }
                None => return,
            }
        }
    }
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut p = self.0.borrow_mut();
        let n = buf.len().min(p.out.len());
        for slot in buf.iter_mut().take(n) {
            *slot = p.out.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut p = self.0.borrow_mut();
        p.input.extend_from_slice(buf);
        p.step();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---- response builders --------------------------------------------------------------------------------------------

/// A cell of `fill` bytes.
pub fn cell(fill: u8) -> Cell {
    Cell::from_bytes(&[fill; 4096]).unwrap()
}

pub fn ok(cmd_seq: u32) -> Response {
    Response {
        cmd_seq,
        cmd: ResponseCmd::Ok,
    }
}

pub fn err(cmd_seq: u32, code: ErrCode) -> Response {
    Response {
        cmd_seq,
        cmd: ResponseCmd::Err(code),
    }
}

pub fn cellr(cmd_seq: u32, c: Cellr) -> Response {
    Response {
        cmd_seq,
        cmd: ResponseCmd::Cellr(c),
    }
}

pub fn dummy(cmd_seq: u32) -> Response {
    cellr(cmd_seq, Cellr::Dummy { cell: cell(0x11) })
}
