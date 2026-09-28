# supply-chain/ — cargo-vet

`cargo vet` checks that every third-party crate in `Cargo.lock` is covered by an audit for the criteria we
require (`safe-to-deploy` by default). Policy: docs/06 §3, ADR-015. Run by `cargo xtask ci-fast` (step 3) as
`cargo vet --locked`, followed by the `vet-closure` policy check.

## Files

| File | Content | Edited by |
|---|---|---|
| `config.toml` | imports, policy, **exemptions** | `cargo vet` + humans (reviewed) |
| `audits.toml` | our own audits (named human reviewers only) and publisher-trust entries (reviewer-approved, below) | humans; `cargo vet trust` |
| `imports.lock` | the imported audits relevant to our graph, pinned | `cargo vet` |

## Imports

Mozilla, Google, ISRG, Bytecode Alliance and Zcash (docs/06 §3), added with `cargo vet import <name>` from the
cargo-vet registry. `imports.lock` pins what was fetched; CI runs `--locked` and never fetches new audits.

## How a dependency becomes acceptable

1. **Direct dependency** (listed in a crate's `Cargo.toml`): needs an ADR line in `docs/08-decisions.md` (why,
   alternatives, maintenance and audit status), passing `cargo deny check`, the 7-day cooldown, **and** either
   an imported audit or a local audit recorded with `cargo vet certify` **by a named human reviewer**. An AI
   agent never records itself as auditor.
2. **Transitive dependency not covered by an import**: covered by a **publisher-trust** entry if its publisher
   qualifies (below), otherwise recorded as a **tracked exemption** (below).
3. **The dependency closure of `secmp-crypto` and `secmp-proto` must have zero exemptions.** `cargo xtask
   policy` fails if any exempted crate is reachable from either crate (all dependency kinds).

## Publisher trust

docs/06 §3 (M0 review, ADR-015 update): a `cargo vet trust` entry is permitted for an individual publisher whom
at least two of the imported audit sets trust. Entries live in `audits.toml` with `criteria = "safe-to-deploy"`,
an `end` date at most 12 months out and a note naming the importing organisations; they are reviewed at every
release (renewed, or replaced by audits/exemptions). Trust entries are not exemptions: they cover only the
versions that publisher published in the `start`–`end` window (`imports.lock` pins the publisher of each
version), and the zero-exemption rule for the `secmp-crypto`/`secmp-proto` closure is unaffected.

Currently trusted (approved in the M0 review, `end = 2027-09-28`): **dtolnay** (crates.io user 3618) and
**BurntSushi** (user 189) — both trusted by the Mozilla, ISRG and Bytecode Alliance audit sets. Added with

```sh
cargo vet trust --all <login> --criteria safe-to-deploy --end-date <YYYY-MM-DD> \
  --notes "Publisher trust (docs/06 §3, …): publisher trusted by >= 2 imported audit sets (…); reviewed at every release."
```

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
Google/Mozilla audits; the other 10 are covered by the publisher-trust entries for dtolnay and BurntSushi (the
ten tracked exemptions of the first M0 state were removed after the M0 review). `cargo vet --locked`: *Vetting
Succeeded (11 fully audited)*; **no exemptions**. The `secmp-crypto`/`secmp-proto` closure is empty.
