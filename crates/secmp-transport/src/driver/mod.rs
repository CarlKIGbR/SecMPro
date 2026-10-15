// SPDX-License-Identifier: AGPL-3.0-or-later
//! The asynchronous side of the transport (ADR-051 Part 1, OPEN-M6-01/-10): the [`AsyncQueueTransport`] trait of spec
//! §12.1, the [`AsyncSession`] and [`AsyncRelayQueueTransport`] over any `tokio::io` stream, and the
//! [`StreamProvider`] that opens such streams (the Tor and TLS providers, the in-process providers of the testkit).
//!
//! The trait carries the seven §12.1 operations with `&mut self` and returns `impl Future + Send` (native `async fn` in
//! traits; no `async-trait` crate, ADR-051 Part 1.3). The synchronous [`crate::QueueTransport`] stays for the M5
//! harness. Neither side reads a clock: time comes in as arguments (AD-11).

use core::future::Future;

use secmp_crypto::SecretBytes;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::{LinkBlob, RelayRef};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::caps::{RecvCap, SendCap};
use crate::error::Result;
use crate::relay_queue::{
    Bucket, CellId, FetchMultiOutcome, LdId, LinkGetMode, LinkGetOutcome, SendOutcome, Token,
};

mod relay_queue;
mod session;

pub use relay_queue::AsyncRelayQueueTransport;
pub use session::{AsyncConnectOutcome, AsyncSession};

/// The operations the sessions need of a relay (spec §12.1), asynchronous. Every method takes `&mut self` (a link
/// carries one command sequence) and returns a `Send` future.
pub trait AsyncQueueTransport {
    /// Create the queue of `recv` and `send` (idempotent, spec §9.1).
    fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &Token,
    ) -> impl Future<Output = Result<(RecvCap, SendCap)>> + Send;

    /// `SEND` one cell.
    fn send(
        &mut self,
        to: &SendCap,
        cell: &Cell,
    ) -> impl Future<Output = Result<SendOutcome>> + Send;

    /// `FETCH` with the cumulative `ack`: the real cells (at most `F` = 4), ascending; dummies filtered.
    fn fetch(
        &mut self,
        from: &RecvCap,
        ack: CellId,
    ) -> impl Future<Output = Result<Vec<(CellId, Cell)>>> + Send;

    /// `FETCH_MULTI` over 1 to 32 queues.
    fn fetch_multi(
        &mut self,
        from: &[(&RecvCap, CellId)],
    ) -> impl Future<Output = Result<FetchMultiOutcome>> + Send;

    /// `QUEUE_DEL`.
    fn delete_queue(&mut self, q: &RecvCap) -> impl Future<Output = Result<()>> + Send;

    /// `LINK_PUT` (three frames).
    fn put_link_data(
        &mut self,
        id: LdId,
        owner: &SecretBytes<32>,
        blob: &LinkBlob,
        one_time: bool,
        expires: Bucket,
        token: &Token,
    ) -> impl Future<Output = Result<()>> + Send;

    /// `LINK_GET`.
    fn get_link_data(
        &mut self,
        id: LdId,
        mode: LinkGetMode<'_>,
    ) -> impl Future<Output = Result<LinkGetOutcome>> + Send;
}

/// What a provider isolates a connection by (spec §8.1: a Tor circuit per link; the scheduler hands out a fresh value
/// for every connection, reconnects included).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Isolation(pub u64);

/// A stream a provider hands out: bytes in both directions, owned, movable between tasks.
pub trait ProviderStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProviderStream for T {}

/// Opens byte streams to relays (spec §12.2: the scheduler is transport-agnostic and names no concrete provider —
/// TEST-SPEC-M6 AD-10). The SecMP-LINK handshake runs on the stream afterwards; a provider never sees a frame's content.
pub trait StreamProvider: Send + Sync {
    /// The stream type.
    type Stream: ProviderStream;

    /// Open a stream to `relay`, isolated by `isolation` (one circuit per connection over Tor).
    ///
    /// # Errors
    /// [`crate::Error::Closed`] if no stream could be opened; a provider's own refusals (Tor not ready, no direct
    /// endpoint) map to its documented errors and never to another provider (CLAUDE.md §1.5).
    fn connect(
        &self,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> impl Future<Output = Result<Self::Stream>> + Send;
}
