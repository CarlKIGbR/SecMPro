// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! One side of a conversation over relay queues (spec §7, §9.1, §9.3): a ratchet state, the queue it receives on,
//! the queue it sends to, and the receiver bookkeeping of §9.3 — the cumulative acknowledgement, the dedup set of
//! `cell_id`s. Used by the harness scenarios; M6 replaces the polling by the constant-rate scheduler.
//!
//! **Receiving (§9.3).** Every delivered cell is acknowledged whether or not it decrypted: a cell that fails to
//! decrypt is discarded and the acknowledgement moves past it. The state a decrypt produced is committed before the
//! acknowledgement is sent (persist-before-ack, §7.5); a cell is sealed under a state that is committed before the
//! cell is sent (persist-before-send).

use std::collections::BTreeSet;

use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::{Entropy, FixedEntropy, RatchetState};
use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, Cell, Content, ContentBody};
use secmp_transport::{Error, QueueTransport, RecvCap, SendCap, SendOutcome};

/// The two ends of a ratchet session started from one shared secret (M3's `init_initiator` / `init_responder`; no
/// SecMP-HX): the initiator sends first.
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn ratchet_pair(
    sk: &SecretBytes<32>,
    transcript: &[u8; 32],
    initiator_entropy: &mut FixedEntropy,
    responder_entropy: &mut FixedEntropy,
) -> (RatchetState, RatchetState) {
    let spk_dh = responder_entropy.x25519().unwrap();
    let rpk_kem = responder_entropy.mlkem768().unwrap();
    let spk_pk = X25519Pk::from_bytes(spk_dh.public_key().as_bytes()).unwrap();
    let rpk_ek = MlKem768Ek::from_bytes(rpk_kem.encapsulation_key().as_bytes()).unwrap();
    let initiator =
        RatchetState::init_initiator_with(sk, transcript, &spk_pk, &rpk_ek, initiator_entropy)
            .unwrap();
    let responder = RatchetState::init_responder(sk, transcript, spk_dh, rpk_kem).unwrap();
    (initiator, responder)
}

/// A Content of one text message.
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn text_content(seq: u64, payload: &[u8]) -> Content {
    let mut msg_id = [0_u8; 16];
    msg_id
        .get_mut(..8)
        .unwrap()
        .copy_from_slice(&seq.to_be_bytes());
    Content {
        seq,
        ts: 1_700_000_001,
        body: ContentBody::Batch(BatchBody {
            messages: vec![AppMessage {
                msg_id,
                kind: AppKind::Text,
                expire_after: 0,
                payload: Zeroizing::new(payload.to_vec()),
            }],
        }),
    }
}

/// The payload of the one text message a Content carries.
#[must_use]
pub fn text_of(content: &Content) -> Option<Vec<u8>> {
    match &content.body {
        ContentBody::Batch(b) => b.messages.first().map(|m| m.payload.to_vec()),
        _ => None,
    }
}

/// What one `FETCH` made of the cells it returned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Polled {
    /// Real cells the relay returned.
    pub fetched: usize,
    /// Of those, cells not seen before that decrypted.
    pub delivered: usize,
    /// Of those, cells not seen before that did not decrypt (discarded, acknowledged).
    pub discarded: usize,
}

/// One side of a conversation.
pub struct Side {
    state: Option<RatchetState>,
    recv: RecvCap,
    send: SendCap,
    committed_ack: u64,
    seen: BTreeSet<u64>,
    received: Vec<Vec<u8>>,
    discarded: usize,
    next_seq: u64,
}

impl Side {
    /// A side that receives on `recv`, sends to `send`, and ratchets with `state`.
    #[must_use]
    pub const fn new(state: RatchetState, recv: RecvCap, send: SendCap) -> Self {
        Self {
            state: Some(state),
            recv,
            send,
            committed_ack: 0,
            seen: BTreeSet::new(),
            received: Vec::new(),
            discarded: 0,
            next_seq: 1,
        }
    }

    /// The payloads delivered so far, in delivery order.
    #[must_use]
    pub fn received(&self) -> &[Vec<u8>] {
        &self.received
    }

    /// The cells discarded because they did not decrypt.
    #[must_use]
    pub const fn discarded(&self) -> usize {
        self.discarded
    }

    /// The cumulative acknowledgement the next `FETCH` carries.
    #[must_use]
    pub const fn committed_ack(&self) -> u64 {
        self.committed_ack
    }

    /// The queue this side receives on.
    #[must_use]
    pub const fn recv_cap(&self) -> &RecvCap {
        &self.recv
    }

    /// The queue this side sends to.
    #[must_use]
    pub const fn send_cap(&self) -> &SendCap {
        &self.send
    }

    /// Replace the queue this side sends to (a route update, or the same queue re-created).
    pub fn set_send_cap(&mut self, send: SendCap) {
        self.send = send;
    }

    /// Replace the queue this side receives on.
    pub fn set_recv_cap(&mut self, recv: RecvCap) {
        self.recv = recv;
    }

    /// Seal `payload` as the next cell and `SEND` it (persist-before-send).
    ///
    /// # Errors
    /// The transport's errors; [`Error::Invalid`] if the ratchet refuses.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn send_text<T: QueueTransport>(
        &mut self,
        transport: &mut T,
        entropy: &mut FixedEntropy,
        payload: &[u8],
    ) -> Result<SendOutcome, Error> {
        let content = text_content(self.next_seq, payload);
        let state = self.state.take().ok_or(Error::Invalid)?;
        let sealed = match state.encrypt_with(&content, entropy) {
            Ok(sealed) => sealed,
            Err(refused) => {
                self.state = Some(refused.into_state());
                return Err(Error::Invalid);
            }
        };
        let (state, cell) = sealed.persist(|_| Ok::<(), ()>(())).unwrap();
        self.state = Some(state);
        self.next_seq = self.next_seq.checked_add(1).unwrap();
        transport.send(&self.send, &cell)
    }

    /// One `FETCH` with the committed acknowledgement: decrypt every cell not seen before, commit the state, then
    /// move the acknowledgement past every cell returned.
    ///
    /// # Errors
    /// The transport's errors ([`Error::NoQueue`] after a relay restart).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn poll<T: QueueTransport>(
        &mut self,
        transport: &mut T,
        entropy: &mut FixedEntropy,
    ) -> Result<Polled, Error> {
        let cells = transport.fetch(&self.recv, self.committed_ack)?;
        let mut polled = Polled {
            fetched: cells.len(),
            ..Polled::default()
        };
        for (cell_id, cell) in cells {
            if self.seen.insert(cell_id) {
                if let Some(payload) = self.open(&cell, entropy) {
                    self.received.push(payload);
                    polled.delivered = polled.delivered.checked_add(1).unwrap();
                } else {
                    self.discarded = self.discarded.checked_add(1).unwrap();
                    polled.discarded = polled.discarded.checked_add(1).unwrap();
                }
            }
            // every delivered cell is acknowledged, whether or not it decrypted (§9.3)
            self.committed_ack = self.committed_ack.max(cell_id);
        }
        Ok(polled)
    }

    /// `FETCH` until the relay returns no real cell; the last `FETCH` carries the final acknowledgement, so the
    /// queue ends empty.
    ///
    /// # Errors
    /// As [`Side::poll`].
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn drain<T: QueueTransport>(
        &mut self,
        transport: &mut T,
        entropy: &mut FixedEntropy,
    ) -> Result<usize, Error> {
        let mut delivered = 0_usize;
        loop {
            let polled = self.poll(transport, entropy)?;
            delivered = delivered.checked_add(polled.delivered).unwrap();
            if polled.fetched == 0 {
                return Ok(delivered);
            }
        }
    }

    fn open(&mut self, cell: &Cell, entropy: &mut FixedEntropy) -> Option<Vec<u8>> {
        let state = self.state.take()?;
        match state.decrypt_with(cell.as_bytes(), entropy) {
            Ok(opened) => {
                let (state, plaintext) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
                self.state = Some(state);
                text_of(&plaintext.content().ok()?)
            }
            Err(refused) => {
                self.state = Some(refused.into_state());
                None
            }
        }
    }

    /// After the recipient re-created its queue following a relay restart (§9.1): reset the acknowledgement and clear
    /// the dedup set.
    pub fn reset_receiving(&mut self) {
        self.committed_ack = 0;
        self.seen.clear();
    }
}
