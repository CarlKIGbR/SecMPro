# SecMPro

A zero-trust, post-quantum, metadata-free desktop messenger (Linux + Windows) with its own protocol, **SecMP/1**, written in Rust.

- No accounts, no identifiers, no directories — contacts are made by out-of-band invitation and verified with a safety number.
- Every key agreement is a hybrid of X25519 and ML-KEM (FIPS 203); identity keys are Ed25519 ‖ ML-DSA-65.
- Messages travel as fixed-size cells at a constant rate over Tor to a relay that keeps ciphertext in RAM and cannot log, identify or correlate.
- The desktop client removes its windows from the operating system's screenshot and screen-recording APIs (Windows; Linux/Wayland on KDE Plasma ≥ 6.7, Hyprland, niri — these Linux exclusions are compositor settings, not a security boundary) and locks content by default on displays that cannot be protected (X11, GNOME, remote sessions).
- v1: one relay + two clients with every security function active. v1.1: peer-to-peer over per-contact onion endpoints with optional personal mailboxes.

**Status:** planning complete; implementation starts with milestone M0. See `docs/07-milestones.md`.

## Documentation

Start with `docs/00-vision-and-scope.md` (document map) and `CLAUDE.md` (rules for the implementing agent). The normative protocol is `docs/03-protocol-spec.md`; the threat model is `docs/01-threat-model.md`.

## Building (after M0)

```
rustup show                 # toolchain pinned by rust-toolchain.toml
cargo xtask ci              # all gates
cargo build --release -p secmp-relay -p secmp-cli -p secmp-ui
cargo xtask win-test        # cross-build for Windows (cargo-xwin) and run tests in the Windows 11 VM
```

## License

To be decided by the owner (see `docs/09-open-questions.md`, OQ-1). Until then: all rights reserved.

## Security

See `SECURITY.md` (created in M0). Please do not open public issues for vulnerabilities.
