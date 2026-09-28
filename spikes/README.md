# spikes/ — M0 build spikes (temporary)

Throw-away programs for the M0 spikes (docs/07 M0, Amendment A1 §4). Each is its **own Cargo workspace**, outside
the product workspace: its dependencies do not enter the product `Cargo.lock`, cargo-deny or cargo-vet. Outcomes
are recorded in `docs/reviews/M0-spikes.md`; this directory is removed afterwards (git history keeps it).

| Spike | What | Where it runs |
|---|---|---|
| `sqlcipher/` (a) | `rusqlite` 0.40.2 `bundled-sqlcipher-vendored-openssl`: key, write, reopen, wrong key fails, file is not plaintext SQLite, `PRAGMA cipher_version` | native `windows-latest`, native Linux, macOS; cross with cargo-xwin (macOS, Linux) |
| `aws-lc/` (b) | `aws-lc-rs` 1.18.1: SHA-256 known answer, X25519 agreement, ML-KEM-768 round trip | same as (a) |
| `slint-hello/` (c) | Slint 1.18.1 (winit backend): a window opens and closes | compiled on macOS, Linux, Windows; opened natively on macOS |
