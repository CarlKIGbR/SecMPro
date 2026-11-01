// SPDX-License-Identifier: AGPL-3.0-or-later
//! The error and the events of the client core's request/response API (`docs/02` §4). One uniform error for the whole
//! crate surface that the UI sees: no variant carries a field with an id, a secret or a message of a lower layer
//! (CLAUDE.md §4). The request/response methods themselves are B-4…B-7; part 1 defines the names the rows of B-1…B-3 use.

use core::fmt;

/// A contact (the row id; also the id of its session).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactId(pub i64);

/// Why an invitation was refused (spec §5.5, TEST-SPEC IN-12): the class is computed locally from the invitation and the
/// opened link data, shown to the user, never logged and never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteReject {
    /// `now ≥ expires`.
    Expired,
    /// The version byte of the invitation or its kind byte is not the one this build speaks.
    Unsupported,
    /// The inviter's identity in the link data is not the one the invitation names.
    Mismatch,
    /// Anything else: a malformed invitation, a link data that does not open, a bundle that does not verify.
    Invalid,
}

impl fmt::Display for InviteReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Expired => "invitation expired",
            Self::Unsupported => "invitation not supported",
            Self::Mismatch => "invitation does not match link data",
            Self::Invalid => "invitation invalid",
        })
    }
}

/// The error of the `Api`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The profile could not be unlocked (uniform: a wrong passphrase, a file that is no profile).
    Unlock,
    /// The store or the environment could not complete the operation; nothing was changed.
    Unavailable,
    /// The contact does not take real messages (it removed us).
    Blocked,
    /// The contact is not verified and the operation needs it.
    Unverified,
    /// The contact came from a restored backup and must be invited again.
    ReinviteRequired,
    /// The operation needs the user's confirmation first.
    ConfirmRequired,
    /// An export path inside a cloud-synchronised folder.
    CloudFolder,
    /// Not supported by this build.
    Unsupported,
    /// An invitation was refused.
    Invitation(InviteReject),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlock => f.write_str("the profile could not be unlocked"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Blocked => f.write_str("the contact does not accept messages"),
            Self::Unverified => f.write_str("the contact is not verified"),
            Self::ReinviteRequired => f.write_str("the contact must be invited again"),
            Self::ConfirmRequired => f.write_str("confirmation required"),
            Self::CloudFolder => f.write_str("the path is inside a cloud-synchronised folder"),
            Self::Unsupported => f.write_str("not supported"),
            Self::Invitation(r) => r.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<secmp_store::Error> for Error {
    fn from(e: secmp_store::Error) -> Self {
        match e {
            secmp_store::Error::Unlock => Self::Unlock,
            secmp_store::Error::Unsupported | secmp_store::Error::TooNew => Self::Unsupported,
            secmp_store::Error::ConfirmRequired => Self::ConfirmRequired,
            secmp_store::Error::CloudFolder => Self::CloudFolder,
            _ => Self::Unavailable,
        }
    }
}

impl From<secmp_proto::Error> for Error {
    /// A protocol refusal on the client's own data (never on untrusted input, which has its own mapping) is the
    /// environment's failure from the caller's point of view.
    fn from(_: secmp_proto::Error) -> Self {
        Self::Unavailable
    }
}

impl From<secmp_crypto::Error> for Error {
    /// As for [`secmp_proto::Error`]: a failure of the client's own keys or of the environment.
    fn from(_: secmp_crypto::Error) -> Self {
        Self::Unavailable
    }
}

/// An event for the user interface (no secret in any field).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A handshake presented the identity of an existing contact (ADR-044 (f), O-29): the new contact `new` was created,
    /// unverified, beside `existing`; nothing was merged.
    DuplicateIdentity {
        /// The contact that already held the identity.
        existing: ContactId,
        /// The contact the handshake created.
        new: ContactId,
    },
    /// An invitation was consumed by someone else: the owner status says used, no handshake came before `expires`.
    InvitationUsedElsewhere,
    /// An unconsumed invitation was retired (Q164, SE-09); `id` is its link-data number.
    InvitationRetired {
        /// The invitation.
        id: u32,
        /// Why.
        reason: RetireReason,
    },
}

/// Why an invitation was retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// The user rotated the identity (spec §7.7; Q164).
    IdentityRotated,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `Display` texts are fixed and carry no detail; `Mismatch` is the text IN-12 pins.
    #[test]
    fn errors_display_fixed_text() {
        assert_eq!(
            InviteReject::Mismatch.to_string(),
            "invitation does not match link data"
        );
        assert_eq!(
            Error::Invitation(InviteReject::Expired).to_string(),
            "invitation expired"
        );
        assert_eq!(
            Error::Unlock.to_string(),
            "the profile could not be unlocked"
        );
        assert_eq!(Error::from(secmp_store::Error::TooNew), Error::Unsupported);
        assert_eq!(Error::from(secmp_store::Error::Unlock), Error::Unlock);
        assert_eq!(
            Error::from(secmp_store::Error::Unavailable),
            Error::Unavailable
        );
        assert_eq!(
            Error::from(secmp_store::Error::ConfirmRequired),
            Error::ConfirmRequired
        );
        assert_eq!(
            Error::from(secmp_store::Error::CloudFolder),
            Error::CloudFolder
        );
        assert_eq!(
            Error::from(secmp_store::Error::Unsupported),
            Error::Unsupported
        );
    }
}
