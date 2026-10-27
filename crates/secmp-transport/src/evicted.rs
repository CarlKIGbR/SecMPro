// SPDX-License-Identifier: AGPL-3.0-or-later
//! The plausibility rule of the `evicted` field of `OK_SEND` (spec §9.3, D.2; M05 review F-4).

/// Whether the `evicted` id of an `OK_SEND` that stored cell `cell_id` is plausible: none, or an id of a cell stored
/// earlier in the same queue, `1 <= id < cell_id` (ids start at 1 and grow by one, spec §9.1). Pure, so a model checker
/// can call it.
#[must_use]
pub const fn evicted_is_plausible(cell_id: u64, evicted: Option<u64>) -> bool {
    match evicted {
        None => true,
        Some(id) => id >= 1 && id < cell_id,
    }
}
