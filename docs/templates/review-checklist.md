# Review checklist — MNN <title>

Reviewer: Fable (and others as assigned) · Date · Verdict: **approved / changes requested / rejected**

The reviewer works from the milestone report *and* the code, never from the report alone. Every "yes" below must be verifiable by pointing at a file, test or output.

## A. Scope and acceptance

- [ ] Every acceptance criterion of the milestone has evidence that actually demonstrates it (not a test that asserts the code equals itself).
- [ ] Nothing outside the milestone's scope was built; nothing in scope was silently dropped.
- [ ] Deviations section is empty or every item has an approved ADR.

## B. Invariants (CLAUDE.md §1)

- [ ] Relay learns nothing new (trace every new field that reaches the relay or the wire).
- [ ] No negotiation/fallback path introduced.
- [ ] All key agreements hybrid; labels match spec Appendix A byte-for-byte.
- [ ] Constant-rate invariant: no code path where activity influences emission (grep `Instant::now`, timers, conditionals on outbox state outside the scheduler).
- [ ] Fail-closed on every error path (look for `unwrap_or_default`, `if let Ok` that swallows, `.ok()`).
- [ ] Secret handling: types, zeroize, no Debug/PartialEq, no logs.
- [ ] Persist-before-send where applicable.
- [ ] Decoders total/exact-fit/canonical; fuzz target exists; negative vectors exist.
- [ ] Dependencies: ADR + vet + cooldown; no git deps; no build scripts.
- [ ] Spec/threat model untouched or ADR'd.

## C. Crypto and protocol (if touched)

- [ ] Construction matches the spec paragraph cited in comments; no local invention.
- [ ] Transcript/AD contents complete (compare with spec lists).
- [ ] Non-contributory DH rejection, `verify_strict`, KEM key validation, seed-only dk storage.
- [ ] Nonce/counter discipline; overflow checks; strict receive ordering.
- [ ] Uniform errors for all authentication failures; constant work on failure.
- [ ] External vectors present and passing on all targets; frozen SecMP vectors unchanged unless the spec version changed.
- [ ] Mutation gate: zero survivors or documented.
- [ ] Formal model updated if a message flow changed; CI runs it.

## D. Platform / client security (if touched)

- [ ] Each CS-* requirement claimed has its test from `04` §7.
- [ ] `unsafe` only in `secmp-sys-mem`/`secmp-sys-desktop`, with SAFETY comments and Miri/unit coverage.
- [ ] Locked mode / alarm behaviour cannot be disabled by settings.
- [ ] a11y gating correct; no content in titles/notifications.

## E. Relay / ops (if touched)

- [ ] No per-request logging (test present); no disk writes; buckets only.
- [ ] Unit/sandbox changes reflected in `deploy/` and the exposure gate.

## F. Evidence quality

- [ ] Commands in the report reproduce on a clean checkout (reviewer ran at least the milestone-specific tests).
- [ ] Numbers are exact, not "all tests pass".
- [ ] Windows evidence comes from the VM run, not from a Linux run.

## G. Findings

| # | Severity (blocker/major/minor/nit) | File:line | Finding | Required action |
|---|---|---|---|---|

## H. Verdict and conditions

Approved when all blockers and majors are closed and re-verified. Record in `docs/reviews/MNN-review.md`.
