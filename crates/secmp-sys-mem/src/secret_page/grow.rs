// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded grow-and-retry policy for locking a data page against a per-process quota of lockable memory (Windows:
//! the minimum working set; docs/04 CS-2.2 "`VirtualLock` (with working-set adjustment)"; ADR-061).
//!
//! Safe and platform-independent: the three operating-system calls come in as closures, so the policy is unit-tested,
//! and run under Miri, on every host. The Windows backend supplies them and calls [`lock_with_growth`] under one
//! process-wide lock, so a step that one thread takes cannot be lost to another thread's read-modify-write of the
//! sizes. Other lockers in the process (`SQLCipher`'s `cipher_memory_security`) do not take that lock and may use up a
//! step before the retry; the policy therefore re-reads the sizes and grows again, with a doubling step, up to a bound.
//!
//! Fail closed (CLAUDE.md §1.5): every way out other than a successful lock is an [`Error`]; nothing proceeds unlocked.

use super::Error;

/// Pages of the first enlargement of the quota; each further enlargement for the same page is twice the previous.
const WORKING_SET_STEP_PAGES: usize = 64;

/// At most this many enlargements for one page: 64 · (2⁸ − 1) = 16 320 pages (63.75 MiB at 4 KiB) in all, about ten
/// times the largest locked demand estimated (DIAG-M7-windows-virtuallock: ≈ 5–6.5 MB with four SE-19 worlds open).
const WORKING_SET_MAX_STEPS: u32 = 8;

/// The minimum working set is never raised above 256 MiB. An engineering bound against a runaway (four times what
/// one page's steps can add, about forty times the estimated demand), not a docs/04 statement: docs/04 states no
/// locked-memory budget (OPEN-M7-B-25). At the bound a lock that still fails is an [`Error`].
const WORKING_SET_MIN_CAP: usize = 268_435_456;

/// Why one lock attempt failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LockError {
    /// The quota of lockable memory is exhausted (Windows `ERROR_WORKING_SET_QUOTA`): enlarging it may help.
    Quota,
    /// Any other failure: enlarging the quota does not help.
    Other,
}

/// The bounds of [`lock_with_growth`], in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Growth {
    /// The first enlargement.
    pub(super) first_step: usize,
    /// At most this many enlargements per lock.
    pub(super) max_steps: u32,
    /// The minimum is never set above this.
    pub(super) cap: usize,
}

impl Growth {
    /// The working-set bounds for pages of `page` bytes.
    pub(super) fn working_set(page: usize) -> Result<Self, Error> {
        Ok(Self {
            first_step: page
                .checked_mul(WORKING_SET_STEP_PAGES)
                .ok_or(Error::new())?,
            max_steps: WORKING_SET_MAX_STEPS,
            cap: WORKING_SET_MIN_CAP,
        })
    }
}

/// One lock attempt: `Ok(true)` locked, `Ok(false)` out of quota, `Err` any other failure.
fn attempt(lock: &mut impl FnMut() -> Result<(), LockError>) -> Result<bool, Error> {
    match lock() {
        Ok(()) => Ok(true),
        Err(LockError::Quota) => Ok(false),
        Err(LockError::Other) => Err(Error::new()),
    }
}

/// Lock with `lock`. While it fails with [`LockError::Quota`]: read the current `(minimum, maximum)` with `sizes`,
/// raise both by the next step (the minimum at most to `growth.cap`) with `set`, and try again, at most
/// `growth.max_steps` times. The sizes are read afresh before every step, so a step that was undone is taken again from
/// the value really in force.
///
/// # Errors
/// [`Error`] if `lock` fails otherwise, `sizes` or `set` fails, the minimum has reached the cap, a size or step
/// overflows, or the lock still fails after the last step.
pub(super) fn lock_with_growth(
    mut lock: impl FnMut() -> Result<(), LockError>,
    mut sizes: impl FnMut() -> Result<(usize, usize), Error>,
    mut set: impl FnMut(usize, usize) -> Result<(), Error>,
    growth: Growth,
) -> Result<(), Error> {
    if attempt(&mut lock)? {
        return Ok(());
    }
    let mut step = growth.first_step;
    for _ in 0..growth.max_steps {
        let (min, max) = sizes()?;
        let target = min.checked_add(step).ok_or(Error::new())?.min(growth.cap);
        let added = target
            .checked_sub(min)
            .filter(|a| *a > 0)
            .ok_or(Error::new())?;
        set(target, max.checked_add(added).ok_or(Error::new())?)?;
        if attempt(&mut lock)? {
            return Ok(());
        }
        step = step.checked_mul(2).ok_or(Error::new())?;
    }
    Err(Error::new())
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    /// One call the policy made, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Lock,
        Sizes,
        Set(usize, usize),
    }

    const PAGE: usize = 4096;
    /// The first step of the production bounds at 4 KiB pages.
    const S: usize = 64 * PAGE;
    const M: usize = 50 * PAGE;
    const X: usize = 345 * PAGE;

    fn bounds() -> Growth {
        Growth {
            first_step: S,
            max_steps: 8,
            cap: WORKING_SET_MIN_CAP,
        }
    }

    /// Run the policy against scripted answers (consumed in order; past the end `lock` answers `Other` and `sizes`/`set`
    /// fail) and return its result and every call it made.
    fn run(
        locks: &[Result<(), LockError>],
        sizes: &[Result<(usize, usize), Error>],
        sets: &[Result<(), Error>],
        growth: Growth,
    ) -> (Result<(), Error>, Vec<Call>) {
        let calls = RefCell::new(Vec::new());
        let mut locks: VecDeque<_> = locks.iter().copied().collect();
        let mut sizes: VecDeque<_> = sizes.iter().copied().collect();
        let mut sets: VecDeque<_> = sets.iter().copied().collect();
        let r = lock_with_growth(
            || {
                calls.borrow_mut().push(Call::Lock);
                locks.pop_front().unwrap_or(Err(LockError::Other))
            },
            || {
                calls.borrow_mut().push(Call::Sizes);
                sizes.pop_front().unwrap_or(Err(Error::new()))
            },
            |min, max| {
                calls.borrow_mut().push(Call::Set(min, max));
                sets.pop_front().unwrap_or(Err(Error::new()))
            },
            growth,
        );
        (r, calls.into_inner())
    }

    const Q: Result<(), LockError> = Err(LockError::Quota);

    /// (a) The race of DIAG-M7-windows-virtuallock: the first step succeeds, but another locker of the process takes the
    /// new quota before the retry. The policy grows again (twice the step) and locks; one step and one retry fail.
    #[test]
    fn grows_again_when_the_grown_quota_is_taken() {
        let (r, calls) = run(
            &[Q, Q, Ok(())],
            &[Ok((M, X)), Ok((M + S, X + S))],
            &[Ok(()), Ok(())],
            bounds(),
        );
        assert_eq!(r, Ok(()));
        assert_eq!(
            calls,
            [
                Call::Lock,
                Call::Sizes,
                Call::Set(M + S, X + S),
                Call::Lock,
                Call::Sizes,
                Call::Set(M + 3 * S, X + 3 * S),
                Call::Lock,
            ]
        );
    }

    /// (b) A step that was undone (the sizes read back are lower than the ones set): the next step starts from the value
    /// read, not from the value set.
    #[test]
    fn re_reads_the_sizes_when_a_step_was_undone() {
        let (r, calls) = run(
            &[Q, Q, Ok(())],
            &[Ok((M, X)), Ok((M, X))],
            &[Ok(()), Ok(())],
            bounds(),
        );
        assert_eq!(r, Ok(()));
        assert_eq!(
            calls,
            [
                Call::Lock,
                Call::Sizes,
                Call::Set(M + S, X + S),
                Call::Lock,
                Call::Sizes,
                Call::Set(M + 2 * S, X + 2 * S),
                Call::Lock,
            ]
        );
    }

    /// (c) The cap: the minimum is raised at most to the cap; once it is there, the policy fails without another set
    /// and without another lock attempt, although a lock beyond the cap would succeed.
    #[test]
    fn fails_at_the_cap_and_never_locks_beyond_it() {
        let cap = WORKING_SET_MIN_CAP;
        let half = S / 2;
        let (r, calls) = run(
            &[Q, Q, Ok(())],
            &[Ok((cap - half, X)), Ok((cap, X + half))],
            &[Ok(()), Ok(())],
            bounds(),
        );
        assert_eq!(r, Err(Error::new()));
        assert_eq!(
            calls,
            [
                Call::Lock,
                Call::Sizes,
                Call::Set(cap, X + half),
                Call::Lock,
                Call::Sizes,
            ]
        );
    }

    /// (d) The quota cannot be set: an error, and no further lock attempt.
    #[test]
    fn fails_closed_when_the_quota_cannot_be_set() {
        let (r, calls) = run(&[Q, Ok(())], &[Ok((M, X))], &[Err(Error::new())], bounds());
        assert_eq!(r, Err(Error::new()));
        assert_eq!(calls, [Call::Lock, Call::Sizes, Call::Set(M + S, X + S)]);
    }

    /// (e) Any other lock failure is an error at once: no growth, no retry.
    #[test]
    fn other_lock_errors_fail_without_growth() {
        let (r, calls) = run(
            &[Err(LockError::Other), Ok(())],
            &[Ok((M, X))],
            &[Ok(())],
            bounds(),
        );
        assert_eq!(r, Err(Error::new()));
        assert_eq!(calls, [Call::Lock]);
    }

    /// (f) The steps double (S, 2S, 4S), and every size and step is computed with checked arithmetic: an overflow is an
    /// error, never a wrapped or saturated size.
    #[test]
    fn steps_double_and_overflow_fails() {
        let (r, calls) = run(
            &[Q, Q, Q, Ok(())],
            &[Ok((M, X)), Ok((M + S, X + S)), Ok((M + 3 * S, X + 3 * S))],
            &[Ok(()), Ok(()), Ok(())],
            bounds(),
        );
        assert_eq!(r, Ok(()));
        let set: Vec<_> = calls
            .iter()
            .filter(|c| matches!(c, Call::Set(..)))
            .copied()
            .collect();
        assert_eq!(
            set,
            [
                Call::Set(M + S, X + S),
                Call::Set(M + 3 * S, X + 3 * S),
                Call::Set(M + 7 * S, X + 7 * S),
            ],
            "doubling steps"
        );

        // the doubled step overflows after the first step
        let huge = Growth {
            first_step: usize::MAX / 2 + 1,
            max_steps: 8,
            cap: usize::MAX,
        };
        let (r, calls) = run(
            &[Q, Q, Ok(())],
            &[Ok((0, 0)), Ok((0, 0))],
            &[Ok(()), Ok(())],
            huge,
        );
        assert_eq!(r, Err(Error::new()), "step overflow");
        assert_eq!(
            calls,
            [
                Call::Lock,
                Call::Sizes,
                Call::Set(usize::MAX / 2 + 1, usize::MAX / 2 + 1),
                Call::Lock,
            ],
            "step overflow"
        );

        // the maximum overflows
        let (r, calls) = run(&[Q, Ok(())], &[Ok((M, usize::MAX))], &[Ok(())], bounds());
        assert_eq!(r, Err(Error::new()), "maximum overflow");
        assert_eq!(calls, [Call::Lock, Call::Sizes], "maximum overflow");
    }

    /// (g) A lock that succeeds at once reads and sets nothing.
    #[test]
    fn first_lock_success_touches_no_sizes() {
        let (r, calls) = run(&[Ok(())], &[Ok((M, X))], &[Ok(())], bounds());
        assert_eq!(r, Ok(()));
        assert_eq!(calls, [Call::Lock]);
    }

    /// (h) The number of steps is bounded: after `max_steps` steps without a lock the policy fails.
    #[test]
    fn stops_after_the_last_step() {
        let mut sizes = Vec::new();
        let mut min = M;
        for _ in 0..9 {
            sizes.push(Ok((min, X)));
            min += 10 * PAGE;
        }
        let (r, calls) = run(&[Q; 10], &sizes, &[Ok(()); 9], bounds());
        assert_eq!(r, Err(Error::new()));
        let count = |c: fn(&Call) -> bool| calls.iter().filter(|x| c(x)).count();
        assert_eq!(count(|c| *c == Call::Lock), 9);
        assert_eq!(count(|c| *c == Call::Sizes), 8);
        assert_eq!(count(|c| matches!(c, Call::Set(..))), 8);
    }

    /// The production bounds: 64 pages first, 8 steps, a 256-MiB cap that the 8 steps of one page cannot pass from a
    /// default working set; an overflowing page size is an error.
    #[test]
    fn working_set_bounds_cover_the_measured_demand() {
        let g = Growth::working_set(PAGE);
        assert_eq!(
            g,
            Ok(Growth {
                first_step: 262_144,
                max_steps: 8,
                cap: 268_435_456,
            })
        );
        // 64 · (2⁸ − 1) pages in all, from the default minimum of about 50 pages
        const { assert!(M + S * 255 < WORKING_SET_MIN_CAP) };
        assert_eq!(Growth::working_set(usize::MAX), Err(Error::new()));
    }

    /// (j) The sizes cannot be read, before the first step or before a later one: an error, and neither a set nor a
    /// further lock attempt.
    #[test]
    fn fails_closed_when_the_sizes_cannot_be_read() {
        let (r, calls) = run(&[Q, Ok(())], &[Err(Error::new())], &[Ok(())], bounds());
        assert_eq!(r, Err(Error::new()), "first step");
        assert_eq!(calls, [Call::Lock, Call::Sizes], "first step");

        let (r, calls) = run(
            &[Q, Q, Ok(())],
            &[Ok((M, X)), Err(Error::new())],
            &[Ok(()), Ok(())],
            bounds(),
        );
        assert_eq!(r, Err(Error::new()), "later step");
        assert_eq!(
            calls,
            [
                Call::Lock,
                Call::Sizes,
                Call::Set(M + S, X + S),
                Call::Lock,
                Call::Sizes
            ],
            "later step"
        );
    }
}
