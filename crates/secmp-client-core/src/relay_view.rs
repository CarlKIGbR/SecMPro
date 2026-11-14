// SPDX-License-Identifier: AGPL-3.0-or-later
//! "What the relay can see" (spec §11.3, `docs/04` UI page): the accepted leakage, word for word as the spec lists it, plus
//! the two sentences that apply to a mode — nothing else is ever shown (Q156).

use crate::scheduler::params::Mode;

/// Items 1–5 of §11.3 (`docs/03:719-723`), verbatim, without their numbers.
pub const LEAKAGE: [&str; 5] = [
    "Per-queue online periods (constant-rate streams start and stop with the client), blurred by §10.6.",
    "Statistical correlation of queues over long observation (lifecycle events), reduced but not eliminated by §10.6; in Balanced/direct modes the grouping is explicit (and direct mode reveals the IP).",
    "Control operations are visible as such, from anonymous one-shot links.",
    "Queue lengths and eviction events (the relay is the store); a *contact* learns from eviction notices that the recipient was offline for more than ~`QUEUE_CAPACITY × P_q`.",
    "Availability: the relay can drop, delay or reorder; gaps in `Content.seq` are surfaced.",
];

/// The grouping sentence of Balanced and Low-bandwidth mode (`docs/03:662`, §10.2).
pub const GROUPING: &str = "The relay learns which queues belong together (accepted).";

/// The sentence of direct mode (`docs/03:231`, §5.2).
pub const IP_EXPOSURE: &str =
    "`direct` is for testing and for users who knowingly accept IP exposure.";

/// The lines of the page for `mode` and the transport: the five items; in Balanced and Low-bandwidth mode — which direct
/// mode implies (§10.2) — the grouping sentence; in direct mode the IP-exposure sentence.
#[must_use]
pub fn relay_view(mode: Mode, direct: bool) -> Vec<&'static str> {
    let mut lines = LEAKAGE.to_vec();
    if direct || !matches!(mode, Mode::Strict) {
        lines.push(GROUPING);
    }
    if direct {
        lines.push(IP_EXPOSURE);
    }
    lines
}
