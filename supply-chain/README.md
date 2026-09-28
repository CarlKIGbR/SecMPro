# supply-chain/ — cargo-vet

`cargo vet` checks that every third-party crate in `Cargo.lock` is covered by an audit for the criteria we
require (`safe-to-deploy` by default). Policy: docs/06 §3, ADR-015. Run by `cargo xtask ci-fast` (step 3) as
`cargo vet --locked`, followed by the `vet-closure` policy check.

## Files

| File | Content | Edited by |
|---|---|---|
| `config.toml` | imports, policy, **exemptions** | `cargo vet` + humans (reviewed) |
| `audits.toml` | our own audits | named human reviewers only |
| `imports.lock` | the imported audits relevant to our graph, pinned | `cargo vet` |

## Imports

Mozilla, Google, ISRG, Bytecode Alliance and Zcash (docs/06 §3), added with `cargo vet import <name>` from the
cargo-vet registry. `imports.lock` pins what was fetched; CI runs `--locked` and never fetches new audits.

## How a dependency becomes acceptable

1. **Direct dependency** (listed in a crate's `Cargo.toml`): needs an ADR line in `docs/08-decisions.md` (why,
   alternatives, maintenance and audit status), passing `cargo deny check`, the 7-day cooldown, **and** either
   an imported audit or a local audit recorded with `cargo vet certify` **by a named human reviewer**. An AI
   agent never records itself as auditor.
2. **Transitive dependency not covered by an import**: recorded as a **tracked exemption** (below).
3. **The dependency closure of `secmp-crypto` and `secmp-proto` must have zero exemptions.** `cargo xtask
   policy` fails if any exempted crate is reachable from either crate (all dependency kinds).

## Tracked-exemption procedure

1. Add the crate with `cargo vet add-exemption <crate> <version>` (or let `cargo vet regenerate exemptions`
   add it), then give the entry a note in exactly this form:

   ```toml
   [[exemptions.<crate>]]
   version = "<version>"
   criteria = "safe-to-deploy"
   notes = "Tracked exemption (supply-chain/README.md): pulled by <direct dependency chain>; <why no audit exists / scope>. Review at every release."
   ```

   `cargo xtask policy` fails on any exemption without a `Tracked exemption` note.
2. Name the exemption in the milestone report (§6 "Dependencies added or bumped").
3. **At every release** (M11/M12 and each later release) the list is reviewed: run `cargo vet suggest`; replace
   exemptions by imported audits where they now exist, by local audits from a named human reviewer, or keep
   them with a refreshed note. `cargo vet prune` removes exemptions that are no longer needed.
4. A version bump of an exempted crate re-enters this procedure; exemptions are never widened silently.

## State at M0

`xtask` depends on `serde_json` (ADR-031), which brings 11 registry crates into `Cargo.lock`: `serde_json`,
`serde_core`, `itoa`, `memchr`, `zmij`, and — through `serde_core`'s `cfg(any())` version lock, never compiled
— `serde`, `serde_derive`, `syn`, `quote`, `proc-macro2`, `unicode-ident`. `quote` is covered by imported
Google/Mozilla audits; the other 10 are not covered at their current versions, because the importing
organisations *trust* their publishers (dtolnay, BurntSushi) instead of auditing them (`cargo vet suggest`
proposes `cargo vet trust`). Whether SecMPro adopts publisher trust is an owner/reviewer decision (M0 report
§8); until then the 10 crates are tracked exemptions. The `secmp-crypto`/`secmp-proto` closure is empty, so
the zero-exemption rule holds trivially in M0.
