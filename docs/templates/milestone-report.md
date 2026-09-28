# Milestone report — MNN <title>

Branch: `mNN-<slug>` · Commit range: `<from>..<to>` · Author: Claude Code (Opus) · Date:

## 1. Plan (written before implementation, updated during)

| Step | What | Proves acceptance criterion | Status |
|---|---|---|---|
| 1 | | | |

## 2. What was built

Short, factual list of crates/modules/files added or changed, and the spec sections they implement (cite `§`).

## 3. Evidence per acceptance criterion

| Criterion (from `07-milestones.md`) | Test / command | Result (summary, exact numbers) |
|---|---|---|
| | `cargo nextest run -p … -- <test>` | pass / N cases |

Attach or link raw outputs where useful (`docs/reviews/MNN-evidence/`). Never include message plaintext, keys or fingerprints from real profiles.

## 4. Gates

| Gate | Result |
|---|---|
| `cargo xtask ci` (Linux) | |
| Windows VM tests (if applicable) | |
| KATs / differential | |
| Fuzz smoke (targets, time, findings) | |
| Mutation (`cargo mutants`) | survivors: 0 / listed in `docs/mutants-accepted.md` |
| Coverage | |
| ProVerif / Kani / Miri (if applicable) | |
| `cargo deny` / `cargo vet` / `cargo audit` / cooldown | |
| Reproducible build (if applicable) | |

## 5. Deviations from spec / plan

None — or each listed with the ADR number that approved it.

## 6. Dependencies added or bumped

| Crate | Version | ADR | Vet record | Reason |
|---|---|---|---|---|

## 7. Open risks and known limitations

## 8. Blocked / questions for the reviewer or owner

## 9. Checklist before requesting review

- [ ] All acceptance criteria evidenced above
- [ ] `cargo xtask ci` green on a clean checkout
- [ ] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [ ] Vectors frozen and reviewed (if changed)
- [ ] Docs/CHANGELOG updated
- [ ] Threat model and spec untouched (or ADR'd)
