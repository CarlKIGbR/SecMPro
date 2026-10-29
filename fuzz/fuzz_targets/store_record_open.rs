// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 FZ-02: the record seal of a secret column (`secmp_store::seal`, ADR-053 item 5 and Amendment 1) on
//! arbitrary (table, column, row, bytes), under the table keys of `kat::TEST_MK`: never panics, and a record opens only
//! where it was sealed.
//!
//! Input: `table u8 ‖ col_len u8 ‖ column ‖ row_len u8 ‖ row_key ‖ mode u8 ‖ bytes`; the table is `Table::ALL[table %
//! 9]` and the column the bytes as given (lossy UTF-8).
//! - Even mode: `bytes` is opened as a record of (table, column, row): the one uniform `Err(Unavailable)`, since random
//!   bytes are no record of that place.
//! - Odd mode: `bytes` is sealed for (table, column, row). It must open there to `bytes`. It must be refused under
//!   another column of the same row (`column` with `"x"` appended), another row (`row_key` with one byte appended) and
//!   another table (the next of `Table::ALL`), and with one byte of the record changed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_store::Error;
use secmp_store::keys::Table;
use secmp_store::seal::{open_kat, seal_kat};

/// The next `n` bytes of `data` after its first, as (head, rest).
fn prefixed(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (n, rest) = data.split_first()?;
    rest.split_at_checked(usize::from(*n))
}

fuzz_target!(|data: &[u8]| {
    let Some((t, rest)) = data.split_first() else {
        return;
    };
    let Some((column, rest)) = prefixed(rest) else {
        return;
    };
    let Some((row, rest)) = prefixed(rest) else {
        return;
    };
    let Some((mode, bytes)) = rest.split_first() else {
        return;
    };
    let index = usize::from(*t) % Table::ALL.len();
    let (Some(table), Some(next)) = (
        Table::ALL.get(index).copied(),
        Table::ALL.get((index + 1) % Table::ALL.len()).copied(),
    ) else {
        return;
    };
    let column = String::from_utf8_lossy(column);
    if mode & 1 == 0 {
        assert_eq!(open_kat(table, &column, row, bytes).err(), Some(Error::Unavailable));
        return;
    }
    let Ok(rec) = seal_kat(table, &column, row, bytes) else {
        return;
    };
    let opened = open_kat(table, &column, row, &rec);
    assert_eq!(opened.as_deref().map(Vec::as_slice).ok(), Some(bytes), "opens where sealed");
    let other_column = format!("{column}x");
    let other_row = [row, &[0]].concat();
    for (name, refused) in [
        ("another column of the row", open_kat(table, &other_column, row, &rec)),
        ("another row", open_kat(table, &column, &other_row, &rec)),
        ("another table", open_kat(next, &column, row, &rec)),
    ] {
        assert_eq!(refused.err(), Some(Error::Unavailable), "{name}");
    }
    let at = usize::from(*mode).wrapping_mul(13) % rec.len();
    let mut bad = rec;
    if let Some(b) = bad.get_mut(at) {
        *b ^= 1;
    }
    assert_eq!(open_kat(table, &column, row, &bad).err(), Some(Error::Unavailable));
});
