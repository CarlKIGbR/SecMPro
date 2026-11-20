// SPDX-License-Identifier: AGPL-3.0-or-later
//! Capture exclusion of the application window (docs/04, CS-1.18). On Windows the window is excluded from screen capture
//! (`WDA_EXCLUDEFROMCAPTURE`) before the first frame is requested; a window that cannot be excluded is never shown — the
//! process ends with a failure (fail closed). Where this platform has no exclusion yet (Linux: M9), nothing is claimed.
//!
//! Two layers act on Windows: the winit window attribute `content_protected`, which winit applies while it creates the window,
//! and the call of `secmp_sys_desktop::set_exclude_from_capture` in the first turn of the event loop after the window exists,
//! followed by a read-back of the affinity that must be `0x11`.

use slint::ComponentHandle;

use crate::screens::MainWindow;

/// The `WDA_EXCLUDEFROMCAPTURE` value of `GetWindowDisplayAffinity`.
pub const EXCLUDED: u32 = 0x11;

/// Why the window may not be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

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

/// Exclude the window from capture and read the affinity back.
///
/// # Errors
/// [`Refused`] if there is no native window, the call fails, or the affinity read back is not [`EXCLUDED`].
#[cfg(windows)]
pub fn apply(window: &slint::Window) -> Result<u32, Refused> {
    let hwnd = hwnd_of(window).ok_or(Refused)?;
    secmp_sys_desktop::set_exclude_from_capture(hwnd).map_err(|_| Refused)?;
    let affinity = secmp_sys_desktop::display_affinity(hwnd).map_err(|_| Refused)?;
    if affinity == EXCLUDED {
        Ok(affinity)
    } else {
        Err(Refused)
    }
}

/// Run `then` with the window as soon as the toolkit has created the native window (the first turn of the event loop after
/// `show`); `then` is not called if the window never comes.
fn when_created(ui: &MainWindow, then: impl FnOnce(&MainWindow) + 'static) {
    use slint::winit_030::WinitWindowAccessor as _;

    let weak = ui.as_weak();
    let _ = slint::spawn_local(async move {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        if ui.window().winit_window().await.is_ok() {
            then(&ui);
        }
    });
}

/// Windows: run `done` with the outcome of [`apply`] as soon as the native window exists; on a refusal the caller ends the
/// process with a failure. Elsewhere there is no exclusion yet (M9) and `done` is not called.
pub fn arm(ui: &MainWindow, done: impl FnOnce(Result<u32, Refused>) + 'static) {
    #[cfg(windows)]
    when_created(ui, move |ui| done(apply(ui.window())));
    #[cfg(not(windows))]
    {
        let _ = (ui, done);
    }
}

/// As [`arm`], for the probe: `done` also runs where there is no exclusion, with `None`.
pub fn arm_probe(ui: &MainWindow, done: impl FnOnce(Option<Result<u32, Refused>>) + 'static) {
    when_created(ui, move |ui| {
        #[cfg(windows)]
        done(Some(apply(ui.window())));
        #[cfg(not(windows))]
        {
            let _ = ui;
            done(None);
        }
    });
}
