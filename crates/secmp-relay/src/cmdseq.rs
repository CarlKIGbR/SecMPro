// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's recorded `cmd_seq` of one link (spec §9.2, reading OPEN-5, ADR-048 (f)).
//!
//! `last` starts at 0. Every request frame that opens and decodes with `cmd_seq > last` sets `last`, whatever the
//! command's outcome; a request with `cmd_seq ≤ last` is not executed and is answered with exactly one ERR 6 frame.
//! `CONT` frames repeat the continued command's `cmd_seq` and are **exempt**: the executor never passes them here.
//! `last` therefore never decreases (Kani `kani_cmd_seq_monotone`).

/// Whether a request is executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// `cmd_seq > last`: recorded, the command runs (unless another rule, e.g. the rate limit, stops it).
    Fresh,
    /// `cmd_seq ≤ last`: not executed, answered with one ERR 6 frame.
    Stale,
}

/// The recorded `cmd_seq` of one link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CmdSeq {
    last: u32,
}

impl CmdSeq {
    /// `last` = 0.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: 0 }
    }

    /// The last recorded `cmd_seq`.
    #[must_use]
    pub const fn last(&self) -> u32 {
        self.last
    }

    /// The decision for a request frame (never a `CONT`) with this `cmd_seq`; a fresh one is recorded.
    pub const fn admit(&mut self, cmd_seq: u32) -> Admit {
        if cmd_seq > self.last {
            self.last = cmd_seq;
            Admit::Fresh
        } else {
            Admit::Stale
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_greater_cmd_seq_is_fresh() {
        let mut s = CmdSeq::new();
        assert_eq!(s.last(), 0);
        assert_eq!(s.admit(0), Admit::Stale);
        assert_eq!(s.admit(1), Admit::Fresh);
        assert_eq!(s.admit(1), Admit::Stale);
        assert_eq!(s.admit(3), Admit::Fresh);
        assert_eq!(s.admit(2), Admit::Stale);
        assert_eq!(s.last(), 3);
        assert_eq!(s.admit(u32::MAX), Admit::Fresh);
        assert_eq!(s.admit(u32::MAX), Admit::Stale);
        assert_eq!(s.last(), u32::MAX);
    }
}
