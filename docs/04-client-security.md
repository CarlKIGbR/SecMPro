# SecMPro — Client Security Requirements (Linux / Windows)

Status: v1 baseline (2026-09-25). Normative for `secmp-ui`, `secmp-sys`, `secmp-store`, `secmp-client-core`. The rationale and the research behind each item are in `docs/research/R3-screen-capture-client-hardening.md`.

Every requirement has an id (`CS-x.y`) so that milestone reports and tests can reference it. Each MUST have at least one automated test or a documented manual verification procedure (`docs/templates/milestone-report.md`).

## 1. Screen-capture resistance

### 1.1 Windows

- **CS-1.1** On every top-level window that can display message content (main window, popups, previews), call `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` immediately after creation and *before* first paint. If the call fails, the window MUST NOT show content; show an error panel instead.
- **CS-1.2** Re-apply and verify (`GetWindowDisplayAffinity`) after every show/restore/minimise, DPI change, monitor change, and on a 250 ms watchdog timer. If the affinity was found cleared, blank the content, show a persistent alarm ("Screen protection was tampered with"), and log a local security event.
- **CS-1.3** Create swap chains with `DXGI_SWAP_CHAIN_FLAG_DISPLAY_ONLY` where the renderer allows it (Slint/wgpu on DX12; verify in the M8 spike; if not possible, document and rely on CS-1.1).
- **CS-1.4** Detect remote sessions (`GetSystemMetrics(SM_REMOTESESSION)`, WTS session change notifications): content is locked in remote sessions unless the user overrides per session.
- **CS-1.5** Mark text-input areas private for Windows Recall (`SetInputScope(IS_PRIVATE)` where applicable) in addition to CS-1.1; never emit `UserActivity` records; suppress Windows notification content (notifications carry no message text).
- **CS-1.6** Harden the process object at start-up: DACL that grants the owning user SID only `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`, adds an **OWNER RIGHTS (S-1-3-4) ACE** with the same limited rights so that the implicit owner `WRITE_DAC`/`READ_CONTROL` cannot be used to rewrite the DACL, and thereby denies `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | WRITE_DAC` to every other process (KeePassXC pattern plus owner-rights restriction). Documented limitation: not effective against `SeDebugPrivilege` (admin).
- **CS-1.7** Process mitigation policies (set via `SetProcessMitigationPolicy` early in `main`, and via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` for any child): `ProcessExtensionPointDisablePolicy` (blocks AppInit DLLs/legacy hooks), `ProcessSignaturePolicy` (Microsoft-signed only, if no incompatible third-party DLL is required), `ProcessImageLoadPolicy` (no remote images), CFG enabled at build (`-C control-flow-guard`). ACG and Win32k lockdown are deferred to the v1.x process split (they break single-process GUI/JIT).
- **CS-1.8** Windows Error Reporting: `WerRegisterExcludedMemoryBlock` for secret regions and a process-wide policy to not write dumps (`SetErrorMode`, and `WerAddExcludedApplication` in the installer).

### 1.2 Linux

- **CS-1.9** The UI runs as a **native Wayland client** (winit Wayland backend). At start-up detect the session: `WAYLAND_DISPLAY` present and the app connected via Wayland → *protected-capable*; `XDG_SESSION_TYPE=x11`, or the app running through XWayland → *unprotected*. Unprotected sessions and protected-capable sessions **without a verified exclusion** (CS-1.10) start in **locked mode**: the contact list is usable, message content is hidden behind a per-session override dialog that explains the risk. Locked mode is the default on every failure path (fail closed) and cannot be disabled permanently by a setting.
- **CS-1.10** Compositor integration (best available). The Linux exclusions are compositor **settings**, not a security boundary: same-user malware can clear them. The client therefore (a) installs/requests them, (b) verifies them every 2 s, and (c) locks content with an alarm if they disappear.
  - KDE Plasma ≥ 6.7 (screenshots and screencasts; 6.6 covers screencasts only): set `excludeFromCapture` for our windows via the KWin scripting/D-Bus interface (or the `z-screen-capture-visibility-v1` protocol once it ships); verify via the KWin window property.
  - Hyprland ≥ 0.50: on first run, offer to install a window rule (`windowrule = no_screen_share, class:^(secmpro)$` — exact syntax verified against the installed version) into `~/.config/hypr/secmpro.conf` and `source` it; verify via `hyprctl clients -j`.
  - niri: same approach with `block-out-from "screen-capture"` in a generated include file; the UI notes that niri's built-in screenshot tool bypasses the rule.
  - GNOME (Mutter) and unknown compositors: no exclusion exists → **locked mode by default** (same as X11) with a per-session override; track upstream (`wayland-protocols` MR !450, `xdg-desktop-portal-gnome` #219).
  - Verified state (protected / partially protected / locked) drives CS-1.18.
- **CS-1.11** Ship a Flatpak (and an unsandboxed tarball). The Flatpak runs Wayland-only (`--socket=wayland`, no `x11`/`fallback-x11`) and attaches a Wayland `security-context`, which restricts *our* process; it does not stop other apps from capturing. Guidance for users on wlroots compositors: run untrusted apps sandboxed (Flatpak) so that they, too, get a security context and lose access to `wlr-screencopy`/`ext-image-copy-capture`.
- **CS-1.12** Best-effort recording detection: watch PipeWire for screencast nodes (`libpipewire` or `pw-dump` polling every 2 s) and, when a screencast is active on a compositor without exclusion, blur content and show "screen is being recorded". Documented as heuristic.

### 1.3 Cross-platform behaviour (both OSes)

- **CS-1.13** **Blur on unfocus:** when the window loses focus or is occluded (winit `Focused(false)`, `Occluded(true)`), message content is replaced by a blurred/blank placeholder within one frame; restored on focus with a 300 ms delay.
- **CS-1.14** **View-once / hold-to-reveal:** `AppMessage.kind = view-once-text` is shown only while the user holds a key/mouse button, for at most 20 s, then irrecoverably deleted locally; copy/select is disabled; a screenshot-protection failure (CS-1.2/1.9) prevents reveal entirely.
- **CS-1.15** **Visible watermark:** an optional (default on) faint diagonal overlay with the *viewer's* own short fingerprint and local time, rendered on the message pane so that any camera capture attributes the leak to the viewing device.
- **CS-1.16** **Clipboard policy:** copying message text is allowed only for normal messages; every copy uses the `arboard` exclusion flags (`exclude_from_history`, `exclude_from_cloud`, `exclude_from_monitoring`; KDE password-manager hint on Linux) and the clipboard is cleared after 45 s if unchanged.
- **CS-1.17** **No content in OS notifications**, no link previews, no thumbnail generation outside the protected window, no window title containing contact names.
- **CS-1.18** **Security status indicator:** a permanent element in the window shows one of: *Protected* (exclusion active and verified), *Partially protected* (blur/view-once only; names why), *Unprotected display — content locked*. The indicator is driven by CS-1.2/1.9/1.10 state and MUST be testable through the core API.

## 2. Memory hygiene

- **CS-2.1** All key material lives in newtypes from `secmp-crypto` that implement `Zeroize`/`ZeroizeOnDrop`, have no `Clone` unless explicitly required, no `Debug` output of contents, no `PartialEq` (use `subtle::ConstantTimeEq`).
- **CS-2.2** Long-lived secrets (master key, IKS, session root keys) are stored in locked, guarded pages: Linux `memfd_secret` where available (kernel ≥ 5.14, falls back to `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK`), Windows `VirtualLock` (with working-set adjustment). Provided by `secmp-sys-mem::SecretPage`.
- **CS-2.3** Core dumps disabled: Linux `RLIMIT_CORE=0` + `prctl(PR_SET_DUMPABLE, 0)`; Windows CS-1.8.
- **CS-2.4** The process never writes secrets to swap deliberately; the installer documentation recommends encrypted swap/hibernation or none.
- **CS-2.5** Secrets are never formatted into logs; `tracing` fields for key types are redacted by type; a CI test greps release binaries for known test-vector secrets to catch accidental embedding.

## 3. Local storage

- **CS-3.1** One SQLCipher database per profile (`rusqlite` with the SQLCipher version bundled by `libsqlite3-sys` — 4.17.0 at the time of writing; the client checks `PRAGMA cipher_version` at start-up and refuses older-than-pinned): `PRAGMA cipher_memory_security = ON`, `temp_store = MEMORY`, `journal_mode = WAL`, `secure_delete = ON`. SQLCipher requires an OpenSSL backend (`bundled-sqlcipher-vendored-openssl`); its cross-compilation to `x86_64-pc-windows-msvc` is spiked in M0 (fallback: plain SQLite with every column sealed by CS-3.3 and a fixed-size dummy-row schema — ADR-027).
- **CS-3.2** Master key `MK_profile` (32 B random) is wrapped twice: (a) with a passphrase-derived key (Argon2id, m=256 MiB, t=3, p=4, per-profile salt) — mandatory; (b) optionally with an OS-keystore-protected key (Windows: CNG/NCrypt key in the Microsoft Platform Crypto Provider (TPM) or DPAPI fallback; Linux: TPM2 via `tss-esapi` or Secret Service via `oo7`) for "unlock with OS login" convenience, which the UI labels as weaker.
- **CS-3.3** Secret columns (IKS, prekeys, ratchet states, outbox plaintext) are additionally sealed per record with `CAEAD` under keys derived from `MK_profile` (`"SecMP-STORE/1 <table>"`) so that a SQLCipher implementation flaw does not expose keys.
- **CS-3.4** Message retention default: keep forever locally but honour per-message `expire_after`; user default settable (e.g., 7 days). Deletion is a real delete + `secure_delete`; view-once content is never written to disk in plaintext-recoverable form (kept only in memory).
- **CS-3.5** Backups: encrypted export file (same wrapping) containing the identity key set, contacts (peer keys, verification state, display names), settings and message history — and **never** ratchet states, skipped keys, prekey secrets or outbox cells (restoring those would roll a ratchet back and reuse message keys). After a restore, every contact must be re-invited (the client explains this before export). Never automatic; never to cloud folders; explicit warning that the file contains identity keys.
- **CS-3.6** Tor state (`arti` data dir) lives next to the profile; it is not secret but is deleted on profile deletion.
- **CS-3.7** Ratchet-state persistence is incremental: chain keys and counters are rewritten per slot; skipped message keys are inserted/deleted individually, so that constant-rate dummies do not rewrite the whole session record every slot.

## 4. Process sandboxing and input

- **CS-4.1** Linux: after initialising Tor sockets and opening the store, restrict the process with Landlock (`landlock` crate; deny all filesystem access except the profile dir and the tor dir; ABI-best-effort) and a seccomp filter (`seccompiler`) denying `execve`, `ptrace`, `process_vm_readv/writev`, `mount`, and other unneeded syscalls (allowlist derived by tracing the test suite in M9).
- **CS-4.2** Windows: CS-1.6/1.7 now; AppContainer/LPAC for the core process in v1.x.
- **CS-4.3** Keylogging: nothing can stop same-user global hooks on Windows or any X11 client; the design accepts this (document), but CS-1.7's extension-point policy and Wayland's input isolation cover the common cases.
- **CS-4.4** Anti-debug is not a security control; no anti-debug tricks are added beyond CS-2.3 (they hurt debuggability and provide no real protection).

## 5. Accessibility policy

- **CS-5.1** Structural UI (navigation, contact list, buttons, settings) is fully exposed to AccessKit / UIA / AT-SPI.
- **CS-5.2** Message *content* nodes are exposed to the accessibility tree only when the user enables **Accessibility mode** in settings; the setting shows a permanent warning that assistive-technology APIs can be used by other programs to read message text. View-once content is never exposed.
- **CS-5.3** Before 1.0, the a11y policy is reviewed with at least one screen-reader user (open question OQ-7).

## 6. Update and distribution security

- **CS-6.1** Releases are reproducible (`06-engineering-standards.md` §6); the client verifies its own binary hash against the signed release manifest on start-up (informational only in v1).
- **CS-6.2** Update manifests are signed with an offline minisign key and carry a monotonically increasing version; the client refuses downgrades. Full TUF (`tough`) is planned for v1.x (ADR-016).
- **CS-6.3** Windows binaries are Authenticode-signed (Azure Artifact Signing or HSM-held key); Linux: signed Flatpak repo + signed tarball with the same minisign key.

## 7. Verification matrix (what M9 must prove)

| Requirement | Test |
|---|---|
| CS-1.1/1.2/1.3 | Automated on the Windows VM: launch the client, capture the desktop through Windows.Graphics.Capture, BitBlt and DXGI duplication; assert the window region contains no client pixels; clear the affinity from another thread in a test build and assert the watchdog alarm within 500 ms |
| CS-1.4 | Automated: simulate `SM_REMOTESESSION` via test hook; assert locked mode |
| CS-1.6/1.7 | Automated: from another user-level process attempt `OpenProcess(PROCESS_VM_READ)`; assert `ERROR_ACCESS_DENIED`; query mitigation policies |
| CS-1.9/1.10 | Automated on Linux CI (nested KWin ≥ 6.7 in a headless Wayland session; sway as a second compositor): assert locked mode under XWayland and on a compositor without exclusion; assert protected state on KWin with `excludeFromCapture` set; portal screencast and screenshot show no client pixels; clearing the KWin property from another process locks content within 2 s |
| CS-1.13/1.14/1.15/1.16/1.18 | Automated UI tests through the core API + screenshot comparison in a nested compositor |
| CS-2.x | Unit tests + Miri on `secmp-sys-mem`; `/proc/self/smaps` check for locked pages; `strings`-based secret-leak check on release binaries |
| CS-3.x | Unit tests; corrupted-file tests; wrong-passphrase timing constant; forensic check that no plaintext appears in the DB file or WAL |
| CS-4.1 | Integration test that the sandboxed process cannot `execve` or open files outside the profile |
