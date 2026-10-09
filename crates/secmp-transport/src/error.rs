// SPDX-License-Identifier: AGPL-3.0-or-later
//! The error of the client transport (spec §9.3 `ERR` codes, §8.5, D.2).
//!
//! The relay's `ERR` code of a command is an outcome of that command ([`Error::Token`] … [`Error::Rate`]); the link
//! stays usable. [`Error::Rejected`] is the one LINK-level verdict (spec §8.5, OPEN-M5-11 A): a frame that does not
//! open, does not decode, or is an authenticated response that does not fit its request — the transport has closed
//! the link and every later call is [`Error::Closed`]. It carries no detail (M3 F19).

use core::fmt;

use secmp_proto::link;
use secmp_proto::wire::frame::ErrCode;

/// What a transport call can end with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `ERR` 1 TOKEN: the access token was refused.
    Token,
    /// `ERR` 2 FULL: the relay's memory budget or the drain refuses new state.
    Full,
    /// `ERR` 3 NOQUEUE (or `present` 2 of a `CELLR`): no such queue; after a relay restart the recipient re-creates
    /// it (spec §9.1).
    NoQueue,
    /// `ERR` 4 AUTH (or `present` 3): the signature or the key is wrong.
    Auth,
    /// `ERR` 5 EXISTS: the link-data id is taken.
    Exists,
    /// `ERR` 6 MALFORMED (or `present` 4): a stale `cmd_seq`, a value out of range, a stale `ack`.
    Malformed,
    /// `ERR` 7 RATE: the request was over the relay's per-link rate and was not executed.
    Rate,
    /// A received frame failed a LINK check or was no valid response to its request; the link is closed.
    Rejected,
    /// The link is closed (the stream ended, or an earlier call was [`Error::Rejected`]).
    Closed,
    /// The link reached `LINK_MAX_FRAMES` or its `cmd_seq` space: open a new link.
    NewLinkRequired,
    /// Randomness or locked memory is unavailable.
    Unavailable,
    /// An argument is outside what a request can carry (a `FETCH_MULTI` of 0 or more than 32 queues, a capability
    /// that does not parse).
    Invalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Token => "relay refused the access token",
            Self::Full => "relay is full",
            Self::NoQueue => "no such queue",
            Self::Auth => "authentication failed",
            Self::Exists => "link data exists",
            Self::Malformed => "relay found the request malformed",
            Self::Rate => "relay rate limit",
            Self::Rejected => "link rejected",
            Self::Closed => "link closed",
            Self::NewLinkRequired => "new link required",
            Self::Unavailable => "unavailable",
            Self::Invalid => "invalid argument",
        })
    }
}

impl std::error::Error for Error {}

/// `Result` with the transport [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// The outcome an `ERR` code of the relay stands for.
    #[must_use]
    pub const fn from_code(code: ErrCode) -> Self {
        match code {
            ErrCode::Token => Self::Token,
            ErrCode::Full => Self::Full,
            ErrCode::NoQueue => Self::NoQueue,
            ErrCode::Auth => Self::Auth,
            ErrCode::Exists => Self::Exists,
            ErrCode::Malformed => Self::Malformed,
            ErrCode::Rate => Self::Rate,
        }
    }
}

impl From<link::Error> for Error {
    fn from(e: link::Error) -> Self {
        match e {
            link::Error::Rejected => Self::Rejected,
            link::Error::CounterOverflow | link::Error::NewLinkRequired => Self::NewLinkRequired,
            link::Error::PayloadTooLong => Self::Invalid,
            link::Error::Unavailable => Self::Unavailable,
        }
    }
}

impl From<secmp_proto::Error> for Error {
    fn from(e: secmp_proto::Error) -> Self {
        match e {
            secmp_proto::Error::Rejected => Self::Invalid,
            secmp_proto::Error::Unavailable => Self::Unavailable,
        }
    }
}

impl From<secmp_crypto::Error> for Error {
    fn from(e: secmp_crypto::Error) -> Self {
        secmp_proto::Error::from(e).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_relay_code_has_its_outcome() {
        let pairs = [
            (ErrCode::Token, Error::Token),
            (ErrCode::Full, Error::Full),
            (ErrCode::NoQueue, Error::NoQueue),
            (ErrCode::Auth, Error::Auth),
            (ErrCode::Exists, Error::Exists),
            (ErrCode::Malformed, Error::Malformed),
            (ErrCode::Rate, Error::Rate),
        ];
        for (code, error) in pairs {
            assert_eq!(Error::from_code(code), error);
        }
        assert_eq!(Error::from(link::Error::Rejected), Error::Rejected);
        assert_eq!(
            Error::from(link::Error::CounterOverflow),
            Error::NewLinkRequired
        );
        assert_eq!(Error::from(link::Error::PayloadTooLong), Error::Invalid);
        assert_eq!(Error::Closed.to_string(), "link closed");
    }
}
