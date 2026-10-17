// SPDX-License-Identifier: AGPL-3.0-or-later
//! The delay before a link or a control operation is attempted again (spec §10.6 (1); OPEN-M6-14, M05 review F-1):
//! `U[0, 180 s]` after a failure, and after `n` consecutive closes before `RELAYINFO` `U[0, min(180 s · 2^(n−1),
//! 3600 s)]`. Drawn from the timing randomness only, so activity cannot move a reconnect (LR-04).

use crate::scheduler::params::{Params, backoff_cap};
use crate::timing::{TimingRng, Unavailable};

/// The delay in milliseconds. `closed_before` counts the consecutive closes before `RELAYINFO`, this one included
/// (0: some other failure, or a first connection).
///
/// # Errors
/// [`Unavailable`] without randomness.
pub fn reconnect_delay(
    params: &Params,
    rng: &mut TimingRng,
    closed_before: u32,
) -> Result<u64, Unavailable> {
    let cap = if closed_before == 0 {
        params.phase_max_ms
    } else {
        backoff_cap(closed_before, params.phase_max_ms, params.backoff_cap_ms)
    };
    rng.uniform(0, cap)
}
