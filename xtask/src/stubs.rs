// SPDX-License-Identifier: AGPL-3.0-or-later
//! Commands that are documented stubs until their milestone. Each explains what it will do and exits with an error, so a stub
//! can never be mistaken for a passing check.

use crate::util::{Result, bail, say};

/// `cargo xtask repro-check` (real in M11).
pub(crate) fn repro_check() -> Result<()> {
    say("cargo xtask repro-check — reproducible release builds (docs/06 §5 step 12, §6).");
    say(
        "From M11: build the release profile with vendored dependencies and the remapped paths in two digest-pinned",
    );
    say(
        "container images (GitHub-hosted runner and a second builder), compare SHA-256 of every artefact, run",
    );
    say("diffoscope on a mismatch, and fail unless all hashes match.");
    bail!("stub in M0: reproducibility is gated from M11")
}

/// `cargo xtask ops-check` (real in M10).
pub(crate) fn ops_check() -> Result<()> {
    say(
        "cargo xtask ops-check — run deploy/check-hardening.sh against the relay host (docs/05 §9, M10).",
    );
    say(
        "From M10: copy the script to the host over SSH/WireGuard (owner-operated), run it, collect the report and",
    );
    say(
        "fail on any deviation from docs/05 (systemd exposure, nftables, sysctl, journald volatile, no swap, ...).",
    );
    bail!("stub in M0: the relay host is not needed before M10")
}
