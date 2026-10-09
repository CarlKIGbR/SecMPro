// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The byte-level check of a captured connection (H-08; spec §8.4, D.1, D.2): after `HS2` the stream is a whole
//! number of 4352-byte units in each direction, and every unit opens under the link's direction key at the next
//! strict counter with a valid 4336-byte ISO/IEC 7816-4 plaintext.

use secmp_crypto::{Aead, Label, Nonce24, SecretBytes};
use secmp_proto::codec::unpad;
use secmp_proto::sizes::{FRAME_LEN, FRAME_PLAINTEXT_LEN};
use secmp_transport::{RelayQueueTransport, Session};

use super::stream::{Capture, HarnessStream};

/// What [`verify_frames`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameCheck {
    /// Frames the client sent after `HS1`.
    pub to_relay: usize,
    /// Frames the relay sent after `HS2`.
    pub to_client: usize,
    /// Every stream length after the handshake is a multiple of 4352.
    pub aligned: bool,
    /// Every unit opened at its counter with valid padding.
    pub all_open: bool,
}

fn open_all(stream: &[u8], key: &[u8; 32], sess_id: &[u8; 16]) -> (usize, bool, bool) {
    let aligned = stream.len().checked_rem(FRAME_LEN) == Some(0);
    let ad = [Label::LinkFrame.as_bytes(), sess_id.as_slice()].concat();
    let key = SecretBytes::<32>::from_slice(key).unwrap();
    let mut count = 0_usize;
    let mut all_open = true;
    for (counter, unit) in stream.as_chunks::<FRAME_LEN>().0.iter().enumerate() {
        let nonce = *Nonce24::from_link_counter(u64::try_from(counter).unwrap()).as_bytes();
        let opened = Aead::open(&key, &nonce, &ad, unit).is_ok_and(|p| {
            p.len() == FRAME_PLAINTEXT_LEN && unpad(&p, FRAME_PLAINTEXT_LEN).is_ok()
        });
        all_open &= opened;
        count = count.checked_add(1).unwrap();
    }
    (count, aligned, all_open)
}

/// Check the capture of the connection `transport` runs over, with the link's own keys.
#[must_use]
pub fn verify_frames(
    transport: &RelayQueueTransport<HarnessStream>,
    capture: &Capture,
) -> FrameCheck {
    verify_session(transport.session(), capture)
}

fn verify_session(session: &Session<HarnessStream>, capture: &Capture) -> FrameCheck {
    let link = session.link_kat();
    let (k_send, k_recv) = link.keys_kat();
    let sess_id = link.sess_id();
    let (to_relay, a1, o1) = open_all(capture.frames_to_relay(), k_send, sess_id);
    let (to_client, a2, o2) = open_all(capture.frames_to_client(), k_recv, sess_id);
    FrameCheck {
        to_relay,
        to_client,
        aligned: a1 && a2,
        all_open: o1 && o2,
    }
}
