// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`AsyncRelayQueueTransport`]: the [`AsyncQueueTransport`] of a SecMP relay over an [`AsyncSession`] — the
//! asynchronous twin of [`crate::RelayQueueTransport`]. Both build and judge their commands with the same sans-IO
//! exchanges (`crate::ops`), so their outcomes and bytes are the same (TEST-SPEC-M6 AD-08).

use secmp_crypto::SecretBytes;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::sizes::HASH_LEN;
use secmp_proto::tr::Entropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::LinkBlob;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{AsyncQueueTransport, AsyncSession};
use crate::caps::{RecvCap, SendCap};
use crate::error::{Error, Result};
use crate::ops::{self, Exchange, LinkPut, Out, QueueNewKeys, Step};
use crate::relay_queue::{
    Bucket, CellId, FetchMultiOutcome, LdId, LinkGetMode, LinkGetOutcome, SendOutcome, Token,
};

/// The asynchronous transport to one relay over one link.
pub struct AsyncRelayQueueTransport<S> {
    session: AsyncSession<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRelayQueueTransport<S> {
    /// A transport over an established [`AsyncSession`].
    #[must_use]
    pub const fn new(session: AsyncSession<S>) -> Self {
        Self { session }
    }

    /// Connect: the SecMP-LINK handshake on `stream` (see [`AsyncSession::connect`]).
    ///
    /// # Errors
    /// As [`AsyncSession::connect`].
    pub async fn connect<E: Entropy + Send>(
        stream: S,
        pinned_fp: [u8; HASH_LEN],
        access_key: Option<&AccessKey>,
        now_unix: u64,
        entropy: &mut E,
    ) -> Result<Self> {
        Ok(Self::new(
            AsyncSession::connect(stream, pinned_fp, access_key, now_unix, entropy).await?,
        ))
    }

    /// The link's session.
    #[must_use]
    pub const fn session(&self) -> &AsyncSession<S> {
        &self.session
    }

    /// The link's `sess_id`.
    #[must_use]
    pub const fn sess_id(&self) -> &Id {
        self.session.sess_id()
    }

    /// Whether the link is closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.session.is_closed()
    }

    /// `PING` (spec §9.3).
    ///
    /// # Errors
    /// Link errors.
    pub async fn ping(&mut self) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        self.run(ops::ping(seq)).await
    }

    async fn run<T: TryFrom<Out, Error = Error>>(&mut self, mut ex: Exchange<T>) -> Result<T> {
        self.session.send(ex.requests()).await?;
        loop {
            let response = self.session.receive(ex.seq(), ex.context()).await?;
            match ex.push(response) {
                Err(_) => return Err(self.session.reject()),
                Ok(Step::More) => {}
                Ok(Step::Done(outcome)) => return outcome,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncQueueTransport for AsyncRelayQueueTransport<S> {
    async fn create_queue(
        &mut self,
        recv: &SecretBytes<32>,
        send: &SecretBytes<32>,
        token: &Token,
    ) -> Result<(RecvCap, SendCap)> {
        let keys = QueueNewKeys::derive(recv, send)?;
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::create_queue(seq, self.session.sess_id(), keys, token)?;
        self.run(ex).await
    }

    async fn send(&mut self, to: &SendCap, cell: &Cell) -> Result<SendOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::send(seq, self.session.sess_id(), to, cell)?;
        self.run(ex).await
    }

    async fn fetch(&mut self, from: &RecvCap, ack: CellId) -> Result<Vec<(CellId, Cell)>> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::fetch(seq, self.session.sess_id(), from, ack)?;
        self.run(ex).await
    }

    async fn fetch_multi(&mut self, from: &[(&RecvCap, CellId)]) -> Result<FetchMultiOutcome> {
        if !ops::fetch_multi_len_ok(from) {
            return Err(Error::Invalid);
        }
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::fetch_multi(seq, self.session.sess_id(), from)?;
        self.run(ex).await
    }

    async fn delete_queue(&mut self, q: &RecvCap) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::delete_queue(seq, self.session.sess_id(), q)?;
        self.run(ex).await
    }

    async fn put_link_data(
        &mut self,
        id: LdId,
        owner: &SecretBytes<32>,
        blob: &LinkBlob,
        one_time: bool,
        expires: Bucket,
        token: &Token,
    ) -> Result<()> {
        let seq = self.session.next_cmd_seq()?;
        let put = LinkPut {
            id,
            owner,
            blob,
            one_time,
            expires,
            access: token,
        };
        let ex = ops::put_link_data(seq, self.session.sess_id(), &put)?;
        self.run(ex).await
    }

    async fn get_link_data(&mut self, id: LdId, mode: LinkGetMode<'_>) -> Result<LinkGetOutcome> {
        let seq = self.session.next_cmd_seq()?;
        let ex = ops::get_link_data(seq, self.session.sess_id(), id, &mode)?;
        self.run(ex).await
    }
}
