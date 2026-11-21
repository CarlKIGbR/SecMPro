// SPDX-License-Identifier: AGPL-3.0-or-later
//! The bridge between the UI thread and the core: a thread of its own owns the [`Backend`] (in the application the client
//! core's runtime, as `secmp-cli` runs it), requests reach it through a bounded channel and never block the caller, and
//! responses and events go back through a [`Sink`] (in the application a hop onto the UI's event loop). The UI thread never
//! waits for the core.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use secmp_client_core::Zeroizing;

use crate::vm::{ContactRow, Failure, ModeChoice};

/// A message id.
pub type MsgId = [u8; 16];

/// How many requests may wait for the backend; a request beyond that is refused ([`Busy`]) instead of blocking the UI.
pub const QUEUE_DEPTH: usize = 8;

/// What the UI asks of the core.
pub enum Request {
    /// Create the profile `name`, open it and set `mode`.
    Create {
        /// The profile name.
        name: String,
        /// The passphrase (a secret).
        pass: Zeroizing<Vec<u8>>,
        /// The mode to set.
        mode: ModeChoice,
    },
    /// Open the existing profile `name`.
    Unlock {
        /// The profile name.
        name: String,
        /// The passphrase (a secret).
        pass: Zeroizing<Vec<u8>>,
    },
    /// List the contacts of the open profile.
    Contacts,
    /// "What the relay can see" in `mode`.
    RelayView(ModeChoice),
    /// Issue an invitation.
    InviteCreate,
    /// Accept the invitation `uri` (a capability: a secret).
    InviteAccept(Zeroizing<String>),
    /// Send `text` to `contact`, as the core takes it (batching and fragmenting are the core's).
    Send {
        /// The contact.
        contact: i64,
        /// The text (content).
        text: Zeroizing<String>,
    },
    /// Read a message of the history by its id.
    Load {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
    },
    /// Show a received view-once.
    Reveal {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
    },
    /// The safety number of `contact`.
    SafetyNumber(i64),
    /// Verify `contact` by the digits shown.
    Verify {
        /// The contact.
        contact: i64,
        /// The digits (content).
        digits: Zeroizing<String>,
    },
}

impl core::fmt::Debug for Request {
    /// The variant name only: no name, no passphrase.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Create { .. } => "Create",
            Self::Unlock { .. } => "Unlock",
            Self::Contacts => "Contacts",
            Self::RelayView(_) => "RelayView",
            Self::InviteCreate => "InviteCreate",
            Self::InviteAccept(_) => "InviteAccept",
            Self::Send { .. } => "Send",
            Self::Load { .. } => "Load",
            Self::Reveal { .. } => "Reveal",
            Self::SafetyNumber(_) => "SafetyNumber",
            Self::Verify { .. } => "Verify",
        })
    }
}

/// What the core reports besides answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreEvent {
    /// A contact was added.
    ContactAdded(i64),
    /// A contact was removed.
    ContactRemoved(i64),
    /// A contact's key changed.
    KeyChanged(i64),
    /// A message arrived (`kind` is `AppMessage.kind`; `at_ms` the core's time stamp).
    MessageReceived {
        /// The sender.
        contact: i64,
        /// The message.
        msg_id: MsgId,
        /// `AppMessage.kind`.
        kind: u8,
        /// When (Unix milliseconds).
        at_ms: u64,
    },
    /// A message was relayed.
    Relayed(i64, MsgId),
    /// A message was acknowledged by the contact.
    Delivered(i64, MsgId),
    /// A message was relayed but no receipt came in time.
    NotConfirmed(i64, MsgId),
    /// A view-once was lost with the run that held it.
    ViewOnceLost(MsgId),
    /// The contact's key change did not verify: the session is frozen.
    KeyChangeInvalid(i64),
    /// The contact asked for a new session.
    ResetRequested(i64),
    /// A handshake presented the identity of `existing` and made `new`.
    DuplicateIdentity {
        /// The contact that held the identity.
        existing: i64,
        /// The contact the handshake created.
        new: i64,
    },
    /// An identity succession towards the contact is pending.
    SuccessionPending(i64),
    /// A queue rotation of the contact was deferred.
    RotationDeferred(i64),
    /// An invitation the user accepted was refused, whatever the class (it is never shown).
    InviteFailed,
    /// An invitation was retired (expired, used up or replaced).
    InvitationRetired,
    /// An invitation was used by someone else.
    InvitationUsedElsewhere,
    /// The core's loop stopped for good, or the bridge's thread ended: nothing more is shown.
    Stopped,
    /// The core could not finish something just now and tries again: a transient notice, the screen stays.
    Unavailable,
}

/// What comes back to the UI (`Debug` prints the variant name only: names, URIs and messages are content).
pub enum Response {
    /// The profile is open.
    Opened,
    /// The profile was created but could not be opened: it is to be unlocked.
    NotOpened,
    /// The profile is open, but the mode chosen at creation was not stored.
    OpenedModeNotSaved,
    /// The request did not go through.
    Failed(Failure),
    /// The contacts.
    Contacts(Vec<ContactRow>),
    /// The lines of what the relay can see.
    RelayView(Vec<String>),
    /// The invitation just issued: its URI (a capability: a secret).
    Invitation(Zeroizing<String>),
    /// The accept of an invitation is under way: [`CoreEvent::ContactAdded`] or [`CoreEvent::InviteFailed`] follows.
    Accepting,
    /// The message was queued: its id.
    Sent {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
    },
    /// A message of the history.
    Message {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
        /// When (Unix milliseconds of the store's clock).
        at_ms: u64,
        /// The text (content).
        text: Zeroizing<String>,
    },
    /// The core has no such message in the history.
    MessageMissing {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
    },
    /// The text of a view-once, to be shown while the user holds.
    Revealed {
        /// The contact.
        contact: i64,
        /// The message.
        msg_id: MsgId,
        /// The text (content).
        text: Zeroizing<String>,
    },
    /// The safety number.
    SafetyNumber {
        /// The contact.
        contact: i64,
        /// The digits (content).
        digits: Zeroizing<String>,
    },
    /// Whether the digits matched (the contact is verified then).
    Verified {
        /// The contact.
        contact: i64,
        /// The answer.
        ok: bool,
    },
    /// An event of the core.
    Event(CoreEvent),
}

impl core::fmt::Debug for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Opened => "Opened",
            Self::NotOpened => "NotOpened",
            Self::OpenedModeNotSaved => "OpenedModeNotSaved",
            Self::Failed(_) => "Failed",
            Self::Contacts(_) => "Contacts",
            Self::RelayView(_) => "RelayView",
            Self::Invitation(_) => "Invitation",
            Self::Accepting => "Accepting",
            Self::Sent { .. } => "Sent",
            Self::Message { .. } => "Message",
            Self::MessageMissing { .. } => "MessageMissing",
            Self::Revealed { .. } => "Revealed",
            Self::SafetyNumber { .. } => "SafetyNumber",
            Self::Verified { .. } => "Verified",
            Self::Event(_) => "Event",
        })
    }
}

/// Where responses and events go; it may be called from any thread and must not block.
pub type Sink = Arc<dyn Fn(Response) + Send + Sync>;

/// The side of the bridge that talks to the core. It runs on the bridge's thread, so it may block; events the core raises
/// on its own go to the `events` sink.
pub trait Backend: Send + 'static {
    /// Do what `request` asks and answer it.
    fn handle(&mut self, request: Request, events: &Sink) -> Response;
}

/// Why a request was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// [`QUEUE_DEPTH`] requests are waiting.
    Full,
    /// The bridge's thread is not running (it could not be started or has ended).
    Stopped,
}

/// The UI's handle: requests go in, nothing comes out here.
pub struct Bridge {
    requests: SyncSender<Request>,
    thread: Option<JoinHandle<()>>,
}

impl Bridge {
    /// Start the bridge's thread over `backend`; every answer and event goes to `sink`.
    ///
    /// The thread is created once and runs until the bridge is dropped.
    #[must_use]
    pub fn spawn(backend: impl Backend, sink: Sink) -> Self {
        let (requests, inbox) = sync_channel(QUEUE_DEPTH);
        let thread = std::thread::Builder::new()
            .name("secmp-bridge".to_owned())
            .spawn(move || serve(backend, &inbox, &sink))
            .ok();
        Self { requests, thread }
    }

    /// Queue `request` and return at once.
    ///
    /// # Errors
    /// [`Refused::Full`] if [`QUEUE_DEPTH`] requests are waiting; [`Refused::Stopped`] if the thread is not running.
    pub fn submit(&self, request: Request) -> Result<(), Refused> {
        match self.requests.try_send(request) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(Refused::Full),
            Err(TrySendError::Disconnected(_)) => Err(Refused::Stopped),
        }
    }

    /// End the bridge: the backend finishes the request it is on, then is dropped (which shuts the core down), and the thread
    /// is joined.
    pub fn shutdown(mut self) {
        let thread = self.thread.take();
        drop(self);
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

/// Tells the UI that the bridge's thread ended while the bridge was still wanted (a backend that panicked after it had
/// accepted a request): the request would never be answered otherwise.
struct Dying<'a> {
    sink: &'a Sink,
    armed: bool,
}

impl Drop for Dying<'_> {
    fn drop(&mut self) {
        if self.armed {
            (self.sink)(Response::Event(CoreEvent::Stopped));
        }
    }
}

fn serve(mut backend: impl Backend, inbox: &Receiver<Request>, sink: &Sink) {
    let mut guard = Dying { sink, armed: true };
    while let Ok(request) = inbox.recv() {
        let response = backend.handle(request, sink);
        sink(response);
    }
    // the bridge was dropped: an orderly end
    guard.armed = false;
}
