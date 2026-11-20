# M8 spike — Slint 1.18.1 + winit (ADR-013, ADR-063)

Host: Linux x86_64, no display, no compositor, no Windows VM, no KDE session. 2026-11-20. Result: gate of BRIEF_M8 U1 (as amended by WEISUNG M8-1) met except the xwin step, which could not run on this host (proxy 403, see table); work continued, the gap is reported. Items marked NOT-RUN are owner-operated.

| Item | Result | Evidence |
|---|---|---|
| Build Linux | PASS | `cargo build -p secmp-ui`; `cargo xtask step clippy` (`-D warnings`, whole workspace) PASS; no fontconfig development files needed (ADR-063 (4)) |
| Build Windows (xwin) | PARTIAL | `cargo xtask step windows-cross` could not run here: `cargo xwin` gets 403 from the proxy fetching the MSVC CRT (`aka.ms/vs/17/release/channel`). Substitute: `cargo clippy -p secmp-sys-desktop --target x86_64-pc-windows-msvc --all-targets --locked -- -D warnings` PASS (the WDA bindings and T5). `secmp-ui` is excluded from xwin (ADR-034 A1, through `secmp-client-core`): evidence = `windows-native` job after the push |
| Text rendering | NOT-RUN — owner-operated | needs a display: `secmp-ui --probe` (P1) then open the window; under the testing backend only the strings are checked (T1) |
| IME | NOT-RUN — owner-operated | needs a desktop session with an input method: type into the passphrase field (`LineEdit`) with an IME active |
| AccessKit | PARTIAL | compiled in (`accesskit_winit` 0.33.2; AT-SPI via zbus on Linux, UIA on Windows); every input has an `accessible-label`. Tree contents NOT-RUN: `secmp-ui --probe` P4 states "compiled in"; check with Orca / Accessibility Insights |
| DPI | NOT-RUN — owner-operated | `secmp-ui --probe`, line `PROBE P3` |
| GPU renderer | NOT-RUN — owner-operated | femtovg and software are compiled in; Slint's API reports no renderer name (P2 prints the requested order); force one with `SLINT_BACKEND=winit-femtovg` / `winit-software` and run `secmp-ui --probe` |
| WDA before first paint | NOT-RUN — owner-operated | Windows: `secmp-ui --probe`, line `PROBE P5` must read `affinity=0x11`. Two layers: the winit window attribute `content_protected` (set through `BackendSelector::with_winit_window_attributes_hook`, applied while winit creates the window) and `set_exclude_from_capture(hwnd)` in the first event-loop turn after the native window exists, with read-back `0x11`; a refusal hides the window and exits non-zero. Slint creates the native window inside `show()`, so the second layer cannot be ordered strictly before the first frame; the first layer is what closes that gap and must be confirmed on the VM |
| KWin exclusion from the app | NOT-RUN — owner-operated | no KDE session. Facts below |

## `secmp-ui --probe` on this host (no display)

```
PROBE P6 FAIL session=unknown compositor=unknown
PROBE P1 FAIL no backend: Error initializing winit event loop: ... neither WAYLAND_DISPLAY nor WAYLAND_SOCKET nor DISPLAY is set.
PROBE P2 NOT-RUN no window      (P3, P4, P5 the same)
```

Run on the owner's machines: `secmp-ui --probe` (Windows VM, KDE Wayland, KDE X11, GNOME).

## KWin: which interface the app would call (facts, no implementation)

1. KWin has a per-window property `excludeFromCapture` (read/write, `Q_PROPERTY` of `KWin::Window`): <https://github.com/KDE/kwin/blob/master/src/window.h> (line 799).
2. A client can request it through the Wayland protocol `org_kde_plasma_window_management`, window state bit `exclude_from_capture` (0x200000, since version 20): <https://github.com/KDE/plasma-wayland-protocols/blob/master/src/protocols/plasma-window-management.xml>; KWin turns the request into `setExcludeFromCapture(...)`: <https://github.com/KDE/kwin/blob/master/src/wayland/plasmawindowmanagement.cpp> (line 761).
3. Open for M9 (not checked here, no session): whether KWin lets an unprivileged client bind `org_kde_plasma_window_management` (it is normally restricted to trusted clients), and whether a window rule or the KWin scripting API is the alternative.
