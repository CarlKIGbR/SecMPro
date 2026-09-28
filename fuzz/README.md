# fuzz/ — cargo-fuzz targets

One target for every decoder, the HX/TR/LINK state machines (message sequences) and the relay command
executor (docs/06 §4). Corpora are committed. `ci-full` runs every target for 120 s (fuzz smoke, step 6) with
the pinned nightly (`xtask/src/tools.rs`); nightly CI runs 4 h campaigns. The gate runs exactly the targets
listed in `xtask/src/expect.rs` (`FUZZ_TARGETS`), so a removed target fails CI.

Test code here may use `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the file top (docs/06 §2).

Status: empty in M0 (the first targets arrive in M1).
