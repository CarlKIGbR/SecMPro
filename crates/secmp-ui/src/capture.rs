// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capture exclusion of the application window (docs/04, CS-1.2, CS-1.9, CS-1.18) — fail closed. The display starts
//! [`Locked`](Protection::Locked) and becomes [`Verified`](Protection::Verified) only when the platform has confirmed the
//! exclusion. On Windows the window's display affinity is read before anything sets it (`pre`), then set, then read again
//! (`post`); `Verified` needs `post == 0x11` (`WDA_EXCLUDEFROMCAPTURE`) and no failed call on the way. Every other outcome —
//! no window, no handle, a refused or failed call, another value — leaves the display locked. Where this platform has no
//! exclusion yet (Linux and the rest: M9), nothing is claimed and the display stays locked.
//!
//! Two layers act on Windows: the winit window attribute `content_protected`, which winit applies while it creates the
//! window (so `pre` already reads `0x11` when that layer worked), and the call of `secmp_sys_desktop::set_exclude_from_capture`
//! in the first turn of the event loop after the native window exists.

use crate::screens::MainWindow;
use crate::vm::Protection;

/// The `WDA_EXCLUDEFROMCAPTURE` value of `GetWindowDisplayAffinity`.
pub const EXCLUDED: u32 = 0x11;

/// A call of the platform failed, or there is no window to ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// What the exclusion is asked of: the platform's window.
pub trait Surface {
    /// The display affinity of the window.
    ///
    /// # Errors
    /// [`Refused`] if the platform cannot tell.
    fn affinity(&self) -> Result<u32, Refused>;

    /// Exclude the window from capture.
    ///
    /// # Errors
    /// [`Refused`] if the platform refuses.
    fn exclude(&self) -> Result<(), Refused>;
}

/// The three steps of the check, each with its own outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// The affinity read before anything set it.
    pub pre: Result<u32, Refused>,
    /// The call that sets the exclusion.
    pub set: Result<(), Refused>,
    /// The affinity read after it.
    pub post: Result<u32, Refused>,
}

impl Report {
    /// [`Protection::Verified`] only if no step failed and `post` is [`EXCLUDED`]; every other outcome is
    /// [`Protection::Locked`].
    #[must_use]
    pub fn protection(&self) -> Protection {
        if self.pre.is_ok() && self.set.is_ok() && self.post == Ok(EXCLUDED) {
            Protection::Verified
        } else {
            Protection::Locked
        }
    }
}

/// Read, set, read again — in that order, every step run and recorded.
#[must_use]
pub fn verify(surface: &impl Surface) -> Report {
    let pre = surface.affinity();
    let set = surface.exclude();
    let post = surface.affinity();
    Report { pre, set, post }
}

/// The native window of the application on Windows.
#[cfg(windows)]
struct Hwnd(isize);

#[cfg(windows)]
impl Surface for Hwnd {
    fn affinity(&self) -> Result<u32, Refused> {
        secmp_sys_desktop::display_affinity(self.0).map_err(|_| Refused)
    }

    fn exclude(&self) -> Result<(), Refused> {
        secmp_sys_desktop::set_exclude_from_capture(self.0).map_err(|_| Refused)
    }
}

/// The native window handle of `window`, once the toolkit has created it.
#[cfg(windows)]
fn hwnd_of(window: &slint::Window) -> Option<isize> {
    use slint::winit_030::WinitWindowAccessor as _;
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle as _, RawWindowHandle};

    window
        .with_winit_window(|w| match w.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
            _ => None,
        })
        .flatten()
}

/// Run `then` with the outcome of the check as soon as the toolkit has created the native window (the first turn of the
/// event loop after `show`); `then` gets `Err` if the window never comes or has no handle.
///
/// # Errors
/// [`Refused`] if the task cannot be started; the display then stays locked.
#[cfg(windows)]
fn when_created(
    ui: &MainWindow,
    then: impl FnOnce(Result<Report, Refused>) + 'static,
) -> Result<(), Refused> {
    use slint::ComponentHandle as _;
    use slint::winit_030::WinitWindowAccessor as _;

    let weak = ui.as_weak();
    slint::spawn_local(async move {
        let Some(ui) = weak.upgrade() else {
            then(Err(Refused));
            return;
        };
        let outcome = match ui.window().winit_window().await {
            Ok(_) => hwnd_of(ui.window())
                .map(|hwnd| verify(&Hwnd(hwnd)))
                .ok_or(Refused),
            Err(_) => Err(Refused),
        };
        then(outcome);
    })
    .map(|_| ())
    .map_err(|_| Refused)
}

/// Windows: run `done` with the outcome of the check as soon as the native window exists. Elsewhere there is no exclusion
/// yet (M9): `done` is not called and the display stays locked.
///
/// # Errors
/// [`Refused`] if the check cannot be started; the display stays locked.
pub fn arm(
    ui: &MainWindow,
    done: impl FnOnce(Result<Report, Refused>) + 'static,
) -> Result<(), Refused> {
    #[cfg(windows)]
    {
        when_created(ui, done)
    }
    #[cfg(not(windows))]
    {
        let _ = (ui, done);
        Ok(())
    }
}

/// As [`arm`], for the probe: `done` also runs where there is no exclusion (with `None`), once the native window exists.
///
/// # Errors
/// [`Refused`] if the task cannot be started.
pub fn arm_probe(
    ui: &MainWindow,
    done: impl FnOnce(Option<Result<Report, Refused>>) + 'static,
) -> Result<(), Refused> {
    #[cfg(windows)]
    {
        when_created(ui, move |outcome| done(Some(outcome)))
    }
    #[cfg(not(windows))]
    {
        use slint::ComponentHandle as _;
        use slint::winit_030::WinitWindowAccessor as _;

        let weak = ui.as_weak();
        slint::spawn_local(async move {
            if let Some(ui) = weak.upgrade() {
                // the window's existence is all the probe waits for
                drop(ui.window().winit_window().await);
            }
            done(None);
        })
        .map(|_| ())
        .map_err(|_| Refused)
    }
}
