---
title: "R3 — Screen-capture resistance and desktop client hardening (research brief)"
date: 2026-09-25
status: research input (not normative; the normative documents are docs/04-client-security.md and docs/08-decisions.md)
---

# SecMPro research brief: screen-capture resistance and desktop client hardening (Rust, Windows 10/11 + Linux)

Research date: 2026-09-25. Facts checked against primary sources: Microsoft Learn, freedesktop.org / KDE / GNOME GitLab, crates.io, and upstream source. **UNVERIFIED** = could not confirm from a primary source. Note: the web-search budget was exhausted mid-task; later findings came from direct fetches of primary sources, so a few sub-points are marked UNVERIFIED rather than guessed.

## 0. Bottom line up front
- **Windows:** `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` removes a window from all normal user-mode capture (WGC, BitBlt, PrintScreen, Snipping Tool, Game Bar, Teams/Zoom/OBS, Recall). Microsoft explicitly states it is **not a security boundary**. It is defeated by a same-user attacker with code running in, or injected into, the target process; public proof-of-concept tools exist (see 1.2). Treat it as strong protection against *accidental/casual/OS-AI* capture, not against a determined local attacker.
- **Linux/Wayland:** As of today there is **no merged upstream Wayland protocol or portal flag that lets an app mark its own surface "do not capture."** Exclusion exists only as *compositor/user-side* features (KDE 6.6+, Hyprland, niri). GNOME has none. Wayland's real strength is the opposite guarantee: a normal client cannot read other clients' buffers at all.
- **X11:** capture and keylogging cannot be prevented — any client can read the root window. Must be treated as out of scope / degrade-with-warning.
- **Biggest residual leaks everywhere:** accessibility-API text scraping (UIA / AT-SPI), OS notification + IME surfaces drawn by other processes, same-user malware, and cameras/HDMI. Design around these, not just the screenshot API.
- **Framework recommendation:** Slint 1.18 (winit backend, AccessKit, Wayland-native, exposes the winit window → `WDA_EXCLUDEFROMCAPTURE`). Avoid webview stacks (Tauri/Dioxus-desktop) for the sensitive message view.

---

## 1. Windows

### 1.1 SetWindowDisplayAffinity — exact behaviour
Source: MS Learn `nf-winuser-setwindowdisplayaffinity` (ms.date 2018-12-05, updated 2025-07-01).
- Values: `WDA_NONE`=0; `WDA_MONITOR`=0x01 ("displayed only on a monitor; everywhere else the window appears with no content" → black); `WDA_EXCLUDEFROMCAPTURE`=0x11 (Win10 2004+; "everywhere else, the window does not appear at all"). On pre-2004 builds `WDA_EXCLUDEFROMCAPTURE` silently degrades to `WDA_MONITOR`.
- Requires: top-level window owned by the calling process (returns FALSE otherwise); **DWM composition must be active**.
- Microsoft's own words: "unlike a security feature or an implementation of Digital Rights Management (DRM), there is no guarantee … will strictly protect windowed content."
- Capture paths it blocks (corroborated by IOActive 2026 and community reports): Windows.Graphics.Capture and everything on it (Teams, Zoom, Meet, Discord, OBS-WGC, Xbox Game Bar, Snipping Tool, PrintScreen), GDI BitBlt/PrintWindow, and DXGI Desktop Duplication.
- Kernel mechanism: enforced in `win32kfull!GreProtectSpriteContent` on the window's DWM sprite (research repo ahossu/DWMShield). Ownership is checked in the kernel; cross-process calls fail with `ERROR_ACCESS_DENIED` even when elevated (IOActive).
- Related DXGI swap-chain flag `DXGI_SWAP_CHAIN_FLAG_DISPLAY_ONLY` (Win8+): "restrict presented content to the local displays … not accessible via remote accessing or through the desktop duplication APIs." Complementary to WDA for GPU-rendered surfaces.

### 1.2 Known ways the flag is defeated (threat classification, not a how-to)
- **In-process reset:** any code executing with the target's process identity can call `SetWindowDisplayAffinity(WDA_NONE)` because the flag is per-window and ownership-checked at process level. IOActive, "Signal Windows Desktop: contentProtection Bypass" (2026-08-26), demonstrated this against Signal Desktop via a same-process thread. Public tools (levi52/capture-bypass, Londopy/capture-bypass) use administrator-level DLL injection and a persistent re-strip loop; another (IdaruHack) reads the composed frame via the undocumented `DwmGetDxSharedSurface`/D3D11 shared-surface path (title bar and minimized windows excluded, DX12 exclusive-fullscreen may be black). **Implication for SecMPro:** the flag stops external capture tools, Recall and OS AI; it does not stop malware already inside your process or a local admin. Combine with process-DACL hardening (see §5) and injection resistance.
- **HDMI/hardware capture and phone cameras:** never affected (physical layer). WDA is DWM-only.
- **Remote Desktop:** RDP sessions do not run DWM the same way; the shadowclaude write-up (2026-03-05) states "Remote Desktop sessions disable DWM, which breaks the exclusion." Do not rely on WDA under RDP; detect remote sessions (`GetSystemMetrics(SM_REMOTESESSION)`) and degrade. **UNVERIFIED** whether current Win11 RDP (which does composite) shows a WDA window as black vs omitted — needs a live test.

### 1.3 WebView2 / Chromium / GPU swapchains
- `WDA_EXCLUDEFROMCAPTURE` works on GPU-rendered windows including **DXGI flip-model swapchains** and wgpu/DirectComposition windows, because the flag applies to the top-level window's DWM sprite, not the swapchain — winit and tao both simply call `SetWindowDisplayAffinity` on the HWND (verified in source, §4). Signal Desktop (Electron) and Element (Electron) both use Chromium's `setContentProtection` which maps to this API on Windows.
- **WebView2/Tauri caveat:** WebView2 renders into child windows; the flag is set on the top-level host window and covers children, but hide/show and DPI transitions have caused regressions where the window turns into a black rectangle instead of vanishing (Tauri #14189, Sept 2025; Electron #45990, #47834, 2025). **Re-apply after every show/restore and verify with `GetWindowDisplayAffinity`.**

### 1.4 Windows 11 Recall / Copilot+ "screen understanding"
Sources: MS Learn Recall developer page (updated 2026-02-03) and "Manage Recall" (updated 2025-12-10); Wikipedia timeline.
- Recall is opt-in, Copilot+-only (40+ TOPS NPU, 16 GB RAM, BitLocker/Device Encryption, Windows Hello ESS), snapshots encrypted at rest in a **VBS enclave** with TPM-bound keys. GA rolled out through 2025; EU rollout later; Click-to-Do and Recall shipped as preview on Copilot+ (KB5055627, Apr 2025 preview).
- **App opt-out:** `SetWindowDisplayAffinity(WDA_MONITOR)` (or `WDA_EXCLUDEFROMCAPTURE`) excludes a window from Recall snapshots. Browsers use a different path: `SetInputScope(hwnd, IS_PRIVATE=61)` from msctf.dll marks a private-browsing window (requires a registered http/https handler). This is how Brave (1.81, Aug 2025) blocks Recall — with a documented side effect of forcing IME into private mode (brave-browser #48240).
- Admin/MDM controls: `AllowRecallEnablement`, `DisableAIDataAnalysis`, `SetDenyAppListForRecall` (AUMID/exe list), `SetDenyUriListForRecall`. DRM content and RDP clients (mstsc.exe, VMConnect, AVD, RAIL) are filtered by default; private browsing filtered in Edge/Firefox/Chrome/Chromium 124+.
- **Copilot Vision** (support.microsoft.com, opt-in, off by default): "if the content includes harmful or DRM-protected material, Copilot can't analyze it." No documented per-app exclusion beyond DRM.

### 1.5 Detecting capture attempts
- `GraphicsCaptureSession.IsBorderRequired` (Win10 20348+): the yellow capture border is on by default; an app can only suppress it with user consent (`GraphicsCaptureAccess.RequestAccessAsync` + `graphicsCaptureWithoutBorder` capability). This is the **capturer's** API — a SecMPro window that is WDA-excluded is simply absent from WGC, so there is no clean "someone is capturing me" event for your own window. Practical detection = enumerate running capture tooling / active WGC sessions heuristically (fragile). **Honest verdict: detection is best-effort, not reliable.**

### 1.6 DXGI/PlayReady protected content as an alternative
`DXGI_SWAP_CHAIN_FLAG_RESTRICTED_CONTENT` (0x8), `..._HW_PROTECTED` (0x400, Win10), and Output Protection Manager (OPM) enable HDCP/DRM. OPM realistically requires a Microsoft-issued certificate and is designed for premium video, not chat text. **Not realistic for a chat app** — high friction, hardware-dependent, and hostile to accessibility. Use `DISPLAY_ONLY` + WDA instead.

---

## 2. Linux

### 2.1 The Wayland security model
A normal Wayland client cannot read another client's buffers — this is the core design guarantee. Screenshots/recording must go through either xdg-desktop-portal (`org.freedesktop.portal.Screenshot` / `ScreenCast`, interface v6, with user consent + PipeWire) or **compositor-privileged** protocols: `wlr-screencopy-unstable-v1`, or the newer staging `ext-image-copy-capture-v1` + `ext-image-capture-source-v1` (merged into wayland-protocols 1.37, Aug 2024; MR !124). `ext-image-copy-capture` is a privileged protocol — the compositor decides which clients may bind it.

### 2.2 Is there a Wayland "do not capture" flag for an app's own surface?
**No merged upstream mechanism as of 2026-09-25.** Status of every relevant effort (checked live on gitlab.freedesktop.org):
- `ext-surface-capture-control` — wayland-protocols **MR !450, OPEN** (created 2025-10-11, updated 2026-04-30, by UnionTech). Would let a client mark exclude-regions and get capture-state notifications; explicitly "compositors may ignore … for security/accessibility/policy."
- `sensitive-content-v1` — **MR !384, CLOSED** (2025-03, was the closest analogue to WDA/Android FLAG_SECURE).
- `content-type "sensitive"` — MR !246 CLOSED; `protected_content` content-type — MR !260 CLOSED.
- `ext-sensitive-context-v1` — MR !134, WIP since 2022, still "Needs acks/implementations."
- Umbrella issue: wayland-protocols **issue #95 "Support for Private Windows"** (open since 2022-06, updated 2026-05).
- Weston has a real one: `weston_content_protection` (HDCP + "prevent from appearing in screenshots", enforce/relax modes) — but Weston is embedded/IVI, not a desktop compositor.

### 2.3 Per-compositor exclusion that DOES exist (all user/compositor-driven, not app-settable via a portable API)
- **KDE Plasma (KWin):** `excludeFromCapture` window property — "Exclude this window from ScreenCast. Also applied to all transient windows recursively" (verified in KWin `window.h`). Landed via MR !8442 (merged 2025-11-19, Plasma **6.6**, released 2026-02-17). Follow-ups: "Hide from Screencast" titlebar button (MR !8471, 6.6), persistent window rule (MR !8828, 6.7), and screenshots respect it too (MR !9171, 6.7 = "Hide from Screen Capture"). A client-settable protocol `z-screen-capture-visibility-v1` (KWin MR !8519 + plasma-wayland-protocols MR !120) is **still a draft** — so today it's user-driven, not app-driven.
- **Hyprland:** `no_screen_share` window rule (formerly `noscreenshare`), introduced **0.50.0** (~Aug 2025). Draws a black rectangle for matched windows during screencast, incl. when unfocused. Known bugs: display-scaling (#10669, fixed #10674), closing-fade leak (#11103). It is set by the *user* in config, not by the app.
- **niri:** `block-out-from` window rule with `"screencast"` (portal screencasts only) or `"screen-capture"` (also third-party tools, but interactive built-in screenshot UI still bypasses it — documented caveat).
- **GNOME (Mutter):** **nothing native.** Mutter issue #4104 (open, 2025-05) and xdg-desktop-portal-gnome issue #219 (open, 2026-06) are unresolved feature requests. A third-party gnome-shell extension (`org.displayxr.CaptureExclusion1`, merged 2026-09-21) hacks it via a Clutter paint-timing trick — fragile, not upstream.

### 2.4 Privileged-protocol access control (this is your real Wayland lever)
Because exclusion is weak, the defensive posture on Wayland is to *limit who can capture at all*:
- **security-context-v1** (wayland.app; supported by KWin, Hyprland, Sway 1.9+ [2024-02-24], niri, river, labwc, COSMIC, Treeland; NOT Mutter/Weston). Flatpak attaches a security context to sandboxed apps (Flatpak 1.15.6+, needs wayland-protocols ≥1.32) so the compositor can deny them privileged protocols like screencopy. **Caveat:** `ext-foreign-toplevel-list` and `ext-workspace` can leak window titles past the filter (reported issue).
- **Hyprland permission system** (`ecosystem.enforce_permissions`, off by default): `screencopy` permission defaults to **ASK**; denied apps see a black "permission denied" screen. Also `input-capture` (ASK) and `cursorpos` (ASK).
- **Sway/wlroots:** historically any client could bind screencopy (sway #5118, Hyprland #4432); security-context-v1 is the mitigation.
- **GNOME/KWin D-Bus screenshot APIs are locked down:** GNOME 41+ restricts `org.gnome.Shell.Screenshot` to an allowlist; KWin uses `X-KDE-DBUS-Restricted-Interfaces=org.kde.KWin.ScreenShot2` in the caller's .desktop file → non-authorized processes get "not authorized to take a screenshot."

### 2.5 Detecting active screen recording
- Portal ScreenCast sessions are D-Bus sessions owned by the requesting app; there is no portal API to enumerate *other* apps' sessions. Compositors show a "screen is being shared" indicator, but that's UI, not a client-queryable signal.
- Practical heuristic: watch PipeWire for screencast nodes (e.g. Mutter's `meta-screen-cast-src`, `xdg-desktop-portal-wlr`) via `pw-dump`/libpipewire. Fragile and compositor-specific. **Honest verdict: best-effort only.**

### 2.6 X11 and XWayland
- **X11: capture cannot be prevented.** Any client can `XGetImage` the root window and read every other window; there is also no input isolation (keylogging is trivial). This is architectural.
- **XWayland:** "By design, X11 applications cannot access window or screen contents for Wayland clients" (KDE xwaylandvideobridge README). So a native-Wayland SecMPro window is *not* readable by legacy X11 capture tools — but any X11 client can still capture other X11 clients. XWayland does not isolate X11 clients from each other.
- **Strategy for SecMPro:** Wayland-only for the sensitive UI. At startup detect the session (`XDG_SESSION_TYPE`, `WAYLAND_DISPLAY`); if X11 (or if the app itself is running through XWayland), show a hard warning and disable view-once/ephemeral features, or refuse. Prefer running as a native Wayland client (winit Wayland backend) so you are not an XWayland client yourself.

---

## 3. Cross-platform mitigations that reduce screenshot value

Deterrence, not prevention — classify honestly:
- **View-once / ephemeral display** with a short reveal window; render only on explicit user action. (Note the WhatsApp "View Once" desktop/web history of being trivially defeated — treat as deterrence.) **UNVERIFIED** exact recent CVE/date.
- **Blur / hide on focus loss or when not foreground** (winit `WindowEvent::Focused`, occlusion), "reveal on hover/hold" (Snapchat-style). Cheap, effective against shoulder-surfing and background capture.
- **Visible per-recipient watermark** (recipient ID + timestamp overlaid) — strong deterrent, trivially implemented, survives screenshots by definition.
- **Invisible/forensic watermarking** (per-recipient noise robust to screenshot+recompression): open options — Adobe **TrustMark** (Rust crate `trustmark` 0.2.2, 2025-09; Python `trustmark` 0.9.2), `blind-watermark` (Rust 0.1.3 port + mature Python `blind_watermark` 0.4.4), ShieldMnt `invisible-watermark` (Python, DwtDct/DwtDctSvd). Realistic for images/attachments; **hard for pure live text UI** — you'd watermark rendered frames, costly. Useful for leaked-image attribution.
- **Disable clipboard copy** of sensitive content; auto-clear; on Windows set clipboard-history/cloud exclusion formats (see §5.7).
- **Accessibility lockdown (the important one):** even a perfectly capture-proof window leaks its text to UIA (Windows) / AT-SPI (Linux) — Akamai (2024-12-11) showed UIA reading Slack/WhatsApp message text at the same integrity level. You can withhold the a11y tree (don't expose text to providers), but that **breaks screen readers** — a genuine ethics/a11y tradeoff. Recommended compromise: expose structural/navigation a11y but make message *content* opt-in-revealable, or provide an explicit "accessibility mode" the user turns on knowingly.
- **Prevent Recall indexing:** WDA + (for the browser-like case) `SetInputScope(IS_PRIVATE)`; suppress `UserActivity`.
- **RDP/VNC:** detect remote sessions and degrade; don't trust WDA there.

---

## 4. Rust GUI frameworks (versions verified on crates.io 2026-09-25)

Native-handle / content-protection support (verified in source):
- **winit 0.30.13** (0.31 in beta): `Window::set_content_protected` / `with_content_protected`. Windows impl calls `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE/WDA_NONE)` (verified in `platform_impl/windows/window.rs`). Docs: **"iOS / Android / x11 / Wayland / Web / Orbital: Unsupported."** macOS uses `NSWindowSharingNone`. So on Linux you get nothing from winit — you must use compositor features.
- **tao 0.37 / wry 0.57** (Tauri's windowing): `set_content_protection` → same `WDA_EXCLUDEFROMCAPTURE` on Windows (verified). Electron's `setContentProtection` = same on Windows, `NSWindowSharingNone` on macOS, **no-op on Linux** (Element source comments confirm "Unsupported on Linux").
- **egui/eframe 0.36.2** (2026-09-08): `ViewportCommand::ContentProtected` + `ViewportBuilder::with_content_protected` (via winit, so Windows/macOS only).
- **iced 0.14.0** (2025-12-07): IME/input-method support added, wgpu 29 (master on 29), x11/wayland feature flags. Accessibility via AccessKit is present but historically incomplete — **UNVERIFIED** current screen-reader completeness. No first-class content-protection command; drop to raw-window-handle.
- **Slint 1.18.1** (2026-09-21): winit 0.30 backend (`unstable-winit-030` exposes `WinitWindowAccessor::with_winit_window` → call winit's `set_content_protected`), AccessKit feature (`accessibility`), Skia + femtovg-wgpu (wgpu 30) + experimental Vello renderers, "improved screen reader support for text inputs," strong text/IME. **Best fit for a text-heavy, accessible, GPU-rendered, DPI-aware, Wayland-native chat UI.**
- **gpui 0.2.2** (2025-10-22, Zed's framework, now published): Wayland + X11 + Windows, AccessKit dependency. Windows renderer uses DirectComposition + flip swapchains (`CreateSwapChainForComposition`, `DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL`) — **no `SetWindowDisplayAffinity` in its window impl** (you'd add it). Young API, sparse docs.
- **Xilem 0.4.0** (2025-10-29): experimental; not production-ready for a security product.
- **gtk4-rs 0.11.5 / libadwaita 0.9.2:** Wayland-native, mature IME/a11y (AT-SPI). `gdk4-win32::Win32Surface::handle()` gives the HWND on Windows for applying WDA. No built-in content-protection API. Good Linux citizen; heavier Windows story.
- **Tauri 2.11.6** (v3 alpha out): `app.get_window().set_content_protected(true)` works on Windows (WDA via tao) but has the hide/show black-box bug (#14189). WebView2 also widens the accessibility/text-scraping surface. **Not recommended for the sensitive view.**

**wgpu + WDA:** confirmed compatible — WDA is a top-level-window property independent of the DXGI flip-model swapchain, so a wgpu/DX12/Vulkan-on-DXGI window is excluded correctly. winit/tao apply it to the HWND, not the surface.

**Recommendation:** **Slint 1.18 on the winit backend.** Wrap a small native module: Windows → `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` + `DISPLAY_ONLY` swapchain flag + re-apply on show; Linux → detect compositor and, where available, request KWin/Hyprland/niri exclusion (and rely on security-context-v1 to keep sandboxed capturers out), plus your own blur-on-blur/ephemeral logic. Keep egui as a fallback if you want immediate-mode simplicity.

---

## 5. Client-side memory & storage hardening (Rust, versions 2026-09-25)

### 5.1 Memory zeroing / secrets
- `zeroize` 1.9.0, `secrecy` 0.10.3 — baseline for wiping key material and wrapping secrets.
- `memsec` 0.7.0 (guarded heap alloc, `mlock`), `secmem-alloc` 0.4.0 (secret allocator), `memsecurity` 3.5.2 (encrypted-at-rest in-memory secrets).
- `region` 4.0.1 — cross-platform mlock/VirtualLock/mprotect (guard pages).

### 5.2 Prevent swap & core dumps
- Linux: `mlock`/`mlockall`; `madvise(MADV_DONTDUMP)` (kernel 3.4+) to exclude from core dumps; `MADV_WIPEONFORK` (4.14+); `RLIMIT_CORE=0`; `prctl(PR_SET_DUMPABLE, 0)` — also blocks `PTRACE_ATTACH` and changes /proc/pid ownership (but resets on setuid-exec). `memfd_secret` (5.14+, default-on since 6.5) removes pages from the kernel direct map — strongest available for key pages, subject to RLIMIT_MEMLOCK.
- Windows: `VirtualLock` ("guaranteed not to be written to the pagefile while locked"; needs `SetProcessWorkingSetSize` to lock many pages). Suppress dumps with a restrictive process DACL (see 5.3) and `WerRegisterExcludedMemoryBlock` (Win10 1703+) to keep secret blocks out of WER reports.

### 5.3 Anti-debugging / anti-injection
- Linux: `prctl(PR_SET_DUMPABLE,0)`, Yama `ptrace_scope`. Value is modest against a root/same-user attacker — treat as speed bump, not barrier.
- Windows: harden the **process DACL** to deny `PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION` to others (KeePassXC's `createWindowsDACL` is the reference pattern — blocks `ReadProcessMemory`/`MiniDumpWriteDump` for non-admin; defeated by SeDebugPrivilege). This is also your main defence against the in-process WDA reset in §1.2.

### 5.4 Key storage in OS keystores
- Windows: DPAPI (`windows-dpapi` 0.2.0) or CNG/NCrypt with TPM-backed keys via `MS_PLATFORM_CRYPTO_PROVIDER` ("Microsoft Platform Crypto Provider" = TPM KSP, from `NCryptOpenStorageProvider`). TPM-bound = non-exportable, hardware-sealed.
- Linux: kernel keyring (`linux-keyutils` 0.2.5), Secret Service/libsecret via `oo7` 0.6.0 (pure-Rust) or `keyring` 4.2.0 (cross-platform), TPM2 via `tss-esapi` 7.7.0 (8.0-alpha available).

### 5.5 Full-database encryption
- **rusqlite 0.40.2 with `bundled-sqlcipher` / `bundled-sqlcipher-vendored-openssl`** → SQLCipher (upstream 4.18.0 Aug 2026, 4.19 in progress; baseline SQLite 3.53.4; `PRAGMA cipher_memory_security=ON` for locked/zeroed page cache). Recommended over rolling your own AEAD-over-sqlx: SQLCipher gives page-level AES-256 + HMAC and is battle-tested. Derive the DB key from a keystore/TPM-sealed key, not a raw passphrase.

### 5.6 Process sandboxing & exploit mitigations
- Linux: `landlock` 0.4.7 (kernel Landlock now at ABI v9+: FS access rights, TCP bind/connect ABI4, ioctl ABI5, UNIX-socket/signal scoping ABI6, TSYNC across threads ABI8), `seccompiler` 0.5.0 (seccomp-BPF), plus bubblewrap/Flatpak. Higher-level: `birdcage` 0.8.1, `extrasafe` 0.5.1, `skarn-sandbox` 1.0.1 (unified Seatbelt/Landlock+seccomp/AppContainer).
- Windows: AppContainer/LPAC via `rappct` 0.13.3 (Rust AppContainer/LPAC toolkit). Compiler mitigations: `-C control-flow-guard=y` (CFG, Windows-only); CET/shadow-stack via nightly `-Z cf-protection=full` (std not built with CET by default). ACG (`ProcessDynamicCodePolicy`) **breaks JIT** — fine for pure-Rust, but incompatible if you embed WebView2. Win32k lockdown (`ProcessSystemCallDisablePolicy`) **breaks single-process GUI** — only usable in a multi-process split (network/crypto worker locked down, UI process not). `ProcessExtensionPointDisablePolicy` blocks AppInit DLLs, legacy IMEs and global window hooks (a keylogger vector) — but breaks non-Microsoft legacy IMEs. Set mitigations at process creation via `UpdateProcThreadAttribute`/`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` for full effect. Rust on Linux already ships PIE, NX, RELRO, stack-clash, full ASLR by default (rustc exploit-mitigations doc).
- Secure input: on Windows, `ProcessExtensionPointDisablePolicy` + DACL hardening reduce hook-based keyloggers (cannot stop a same-user global `SetWindowsHookEx` keylogger — architectural). On Wayland, input is isolated by design (no client sees another's input); Hyprland's `input-capture` permission gates the capture protocol. X11 has no input isolation.

### 5.7 Clipboard hygiene
`arboard` 3.6.1 provides the exclusions (verified in source): Windows `exclude_from_history` (`CanIncludeInClipboardHistory`=DWORD 0), `exclude_from_cloud` (`CanUploadToCloudClipboard`=0), `exclude_from_monitoring` (`ExcludeClipboardContentFromMonitorProcessing`); Linux `exclude_from_history` (adds `x-kde-passwordManagerHint` MIME). Plus auto-clear on timer / on unfocus.

---

## 6. Build / distribution

- **Windows code signing:** EV certs **no longer buy instant SmartScreen reputation** (MS Learn smartscreen-reputation, 2026-05-04: "EV certificates no longer bypass SmartScreen … paying a premium … is no longer justified"). Use **Azure Artifact Signing** (formerly Trusted Signing): fully managed, keys in FIPS 140-3 Level 3 HSMs, short-lived certs, Basic/Premium SKUs (updated 2026-05-12). Standard Authenticode via HSM/EV also fine; reputation now built by download volume + clean history.
- **Linux:** signed Flatpak (GPG-signed OSTree repo) and/or signed AppImage; reproducible builds (Signal Desktop ships a Docker-based reproducible-build flow for Linux; macOS/Windows "not available yet" — realistic bar).
- **Update security:** use **TUF**. Rust: `tough` 0.24 + `tuftool` 0.16 (awslabs, active, tuftool-v0.16.0 2026-06-18) for full role separation (root/targets/snapshot/timestamp) and rollback/freeze/mix-and-match protection. Tauri's updater uses mandatory ed25519/minisign signatures (cannot be disabled) but has **no rollback protection** — layer TUF or signed versioned manifests on top for a security product.

---

## 7. How Signal / Threema / Element handle desktop screen security (verified in source)
- **Signal Desktop:** DOES protect on Windows. `main.main.ts` calls `window.setContentProtection(true)` on `ready-to-show`; `Settings.std.ts`: `isContentProtectionSupported` = **Windows only**, enabled by default on **Windows 11+** (`>= 10.0.22000`). User toggle: Settings → Privacy → Screen security. **No protection on Linux or macOS.** Blog "By Default, Signal Doesn't Recall" (2025-05-21) frames it as anti-Recall using the DRM/content-protection flag; acknowledges accessibility-tool breakage. IOActive (2026-08-26) showed the in-process bypass.
- **Element Desktop:** `enableContentProtection` setting, `setContentProtection` — `supported()` returns true **only on win32**; source comments: "Unsupported on Linux," "Broken on macOS (electron #19880)." **Default OFF** (store default `false`).
- **Threema Desktop:** could not fetch source in this session (repo access blocked). **UNVERIFIED** — but it is Electron-based, so at best it has the same Windows-only `setContentProtection` capability; needs a direct check.
- **Pattern:** the whole ecosystem gets meaningful screen protection **only on Windows**, does nothing on Linux, and treats it as anti-Recall deterrence. SecMPro can differentiate by (a) doing the Windows work correctly + re-applying, (b) actually using Wayland compositor exclusion + security-context on Linux, and (c) closing the accessibility/notification leak that all of them ignore.

---

## 8. Achievability matrix (prevented / mitigated / impossible)

| Threat | Windows 10/11 | Linux Wayland | Linux X11 |
|---|---|---|---|
| Casual screenshot / snip / PrintScreen | **Prevented** (WDA) | Compositor-dependent: KDE6.6+/Hyprland/niri **prevented**; GNOME **impossible** (no feature) | **Impossible** |
| Screen-share (Teams/Zoom/OBS/Meet) | **Prevented** (WDA) | Portal screencast: KDE/Hyprland/niri **prevented**; GNOME **impossible** | **Impossible** |
| OS AI (Recall / Copilot Vision) | **Prevented** (WDA/IS_PRIVATE) | n/a | n/a |
| Desktop-duplication / DXGI capture | **Prevented** (WDA + DISPLAY_ONLY) | Blocked unless compositor grants privileged protocol | **Impossible** |
| Same-user malware in your process | **Impossible** to prevent (mitigate: DACL, ACG, injection resistance) | **Impossible** to prevent (mitigate: sandbox) | **Impossible** |
| Accessibility text scraping (UIA/AT-SPI) | **Mitigated** (withhold a11y tree — breaks screen readers) | **Mitigated** (same tradeoff) | **Mitigated** |
| HDMI capture card / phone camera | **Impossible** | **Impossible** | **Impossible** |
| Keylogging | **Mitigated** (extension-point + DACL; not same-user hooks) | **Prevented** by design (input isolation) | **Impossible** |
| Memory/key extraction | **Mitigated** (TPM, VirtualLock, DACL, WER exclude) | **Mitigated** (memfd_secret, mlock, keyring/TPM) | **Mitigated** |

## 9. Recommendation for SecMPro (bullets)
- Build the sensitive UI in **Slint 1.18 (winit)**, native-Wayland on Linux, DPI-aware on Windows; keep the message-content view out of any webview.
- Windows: apply `WDA_EXCLUDEFROMCAPTURE`, re-apply on every show/restore/DPI change, verify with `GetWindowDisplayAffinity`; add `DXGI_SWAP_CHAIN_FLAG_DISPLAY_ONLY`; `SetInputScope(IS_PRIVATE)` on text areas for Recall; harden the process DACL (KeePassXC pattern) and set mitigation policies at creation (multi-process so you can Win32k-lockdown + ACG the crypto/network worker).
- Linux: **Wayland-only** for sensitive content; at runtime request compositor exclusion where available (KWin `excludeFromCapture`, Hyprland `no_screen_share`, niri `block-out-from`) and document that GNOME cannot exclude; ship with a security-context so hostile sandboxed apps can't grab screencopy; detect X11/XWayland and degrade with a visible warning.
- Everywhere: **blur-on-unfocus + view-once + reveal-on-hold**, **visible per-recipient watermark**, and a deliberate accessibility policy (content revealed only in an opt-in a11y mode).
- Storage: rusqlite + SQLCipher with a TPM/keystore-sealed key; zeroize/secrecy/memfd_secret for key material; clipboard exclusions via arboard + auto-clear.
- Distribution: Azure Artifact Signing (Windows), signed reproducible Flatpak (Linux), **TUF via tough** for updates.
- Communicate honestly in-product: screenshot resistance is **deterrence against casual/OS/remote capture**, not a guarantee against a compromised endpoint or a camera.

## 10. Open questions / uncertainties (UNVERIFIED)
- Exact current-Win11 RDP behaviour of WDA windows (black vs omitted) needs a live test.
- iced's present-day screen-reader completeness with AccessKit.
- Threema Desktop's actual screen-security code (repo fetch blocked this session).
- Whether `ext-surface-capture-control` (MR !450) will merge and which compositors will implement the exclude-region path vs only the notify path.
- Robustness of forensic watermarking (TrustMark/blind-watermark) specifically against screenshot→JPEG-recompress→re-screenshot chains at chat resolutions.
- Reliability of PipeWire-based "am I being recorded" detection across GNOME/KDE/wlroots.

## Sources (URLs)
- SetWindowDisplayAffinity: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity
- DXGI_SWAP_CHAIN_FLAG: https://learn.microsoft.com/en-us/windows/win32/api/dxgi/ne-dxgi-dxgi_swap_chain_flag
- Recall (dev): https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/recall/ ; browsers: .../recall/recall-web-browsers ; Manage Recall: https://learn.microsoft.com/en-us/windows/client-management/manage-recall
- Meziantou exclude-from-capture (2025-06-23): https://www.meziantou.net/how-to-exclude-your-windows-app-from-screen-capture-and-recall.htm
- IOActive Signal bypass (2026-08-26): https://www.ioactive.com/signal-windows-desktop-contentprotection-bypass/
- DWMShield: https://github.com/ahossu/DWMShield ; capture-bypass: https://github.com/levi52/capture-bypass ; DwmGetDxSharedSurface tool: https://github.com/IdaruHack/wda-bypass-screenshot-tool
- Signal blog (2025-05-21): https://signal.org/blog/signal-doesnt-recall/ ; Brave (Register 2025-07-23): https://www.theregister.com/2025/07/23/brave_browse_block_microsoft_recall/ ; Brave IME issue: https://github.com/brave/brave-browser/issues/48240
- IsBorderRequired: https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscapturesession.isborderrequired ; Screen capture: https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture
- Copilot Vision: https://support.microsoft.com/en-us/microsoft-copilot/using-copilot-vision-with-microsoft-copilot
- Akamai UIA attack (2024-12-11): https://www.akamai.com/blog/security-research/windows-ui-automation-attack-technique-evades-edr
- Tauri content-protection bug: https://github.com/tauri-apps/tauri/issues/14189 ; Electron: https://github.com/electron/electron/issues/45990 , /47834
- winit set_content_protected: https://docs.rs/winit/latest/winit/window/struct.Window.html (source: rust-windowing/winit windows/window.rs) ; tao source: tauri-apps/tao windows/window.rs ; egui ViewportCommand: https://docs.rs/egui/latest/egui/viewport/enum.ViewportCommand.html
- Slint 1.18 (2026-09-16): https://slint.dev/blog/slint-1.18-released ; iced 0.14 (2025-12-07): https://github.com/iced-rs/iced/releases/tag/0.14.0
- wayland-protocols MRs: !450 https://gitlab.freedesktop.org/wayland/wayland-protocols/-/merge_requests/450 ; !384 (/384); !246 (/246); !134 (/134); issue #95 (/issues/95); ext-image-copy-capture !124 (/124)
- wayland-protocols 1.37 (2024-08): https://lists.freedesktop.org/archives/wayland-devel/2024-August/043774.html ; Phoronix: https://www.phoronix.com/news/Wayland-Merges-Screen-Capture
- KWin MRs: !8442 https://invent.kde.org/plasma/kwin/-/merge_requests/8442 ; !8446 !8471 !8519 !8828 !9171 (same base URL) ; plasma-wayland-protocols !119 !120 ; KWin window.h `excludeFromCapture`
- Plasma schedule (6.6=2026-02-17, 6.7=2026-06-16): https://community.kde.org/Schedules/Plasma_6
- Hyprland no_screen_share (0.50.0): https://alchemmist.xyz/articles/hyrpland-noscreenshare/ ; discussion #12417, #10669 ; Permissions: https://wiki.hypr.land/Configuring/Advanced-and-Cool/Permissions/
- niri window rules block-out-from: https://niri-wm.github.io/niri/Configuration:-Window-Rules.html
- GNOME: mutter issue #4104 https://gitlab.gnome.org/GNOME/mutter/-/work_items/4104 ; xdp-gnome #219 https://gitlab.gnome.org/GNOME/xdg-desktop-portal-gnome/-/work_items/219 ; DisplayXR extension PR https://github.com/DisplayXR/displayxr-runtime/pull/1620
- security-context-v1: https://wayland.app/protocols/security-context-v1 ; sway #5118 ; Hyprland #4432 ; sway 1.9 https://github.com/swaywm/sway/releases/tag/1.9 ; Flatpak NEWS (1.15.6)
- ext-image-copy-capture: https://wayland.app/protocols/ext-image-copy-capture-v1 ; Weston content-protection: https://gitlab.freedesktop.org/wayland/weston/-/raw/main/protocol/weston-content-protection.xml
- Xwayland: https://wayland.freedesktop.org/docs/book/Xwayland.html ; xwaylandvideobridge README (invent.kde.org)
- ScreenCast portal: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html ; PipeWire screencast: https://gist.github.com/columbarius/50239ea3c4c70df8f240aa50f88e801a
- madvise: https://man7.org/linux/man-pages/man2/madvise.2.html ; memfd_secret: .../memfd_secret.2.html ; PR_SET_DUMPABLE: .../PR_SET_DUMPABLE.2const.html ; VirtualLock: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock ; WerRegisterExcludedMemoryBlock (werapi)
- SetProcessMitigationPolicy: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy ; exploit-protection-reference: https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference ; dynamic-code policy (winnt) ; rustc exploit mitigations: https://doc.rust-lang.org/rustc/exploit-mitigations.html ; control-flow-guard: https://doc.rust-lang.org/rustc/codegen-options/index.html ; cf-protection (unstable book)
- CNG TPM provider: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider ; OPM: https://learn.microsoft.com/en-us/windows/win32/medfound/output-protection-manager
- rusqlite sqlcipher features: https://docs.rs/crate/rusqlite/latest/features ; SQLCipher changelog (github sqlcipher/sqlcipher)
- Landlock: https://docs.kernel.org/userspace-api/landlock.html ; crates: landlock 0.4.7, seccompiler 0.5.0, rappct 0.13.3, arboard 3.6.1 (source), keyring 4.2.0, oo7 0.6.0, linux-keyutils 0.2.5, tss-esapi 7.7.0, trustmark 0.2.2, blind-watermark 0.1.3, region 4.0.1, memsec 0.7.0 (all crates.io)
- Clipboard formats: https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats
- TUF: https://theupdateframework.io/docs/overview/ ; tough: https://github.com/awslabs/tough ; Tauri updater: https://v2.tauri.app/plugin/updater/
- SmartScreen/EV: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation ; Azure Artifact/Trusted Signing: https://learn.microsoft.com/en-us/azure/artifact-signing/overview
- Signal Desktop source: main.main.ts, ts/types/Settings.std.ts, reproducible-builds/README.md (github signalapp/Signal-Desktop) ; Element: src/electron-main.ts, src/settings.ts, src/store.ts (github element-hq/element-desktop) ; KeePassXC Bootstrap.cpp (createWindowsDACL)
- AccessKit lazy activation: https://docs.rs/accesskit_windows/latest/accesskit_windows/struct.Adapter.html
