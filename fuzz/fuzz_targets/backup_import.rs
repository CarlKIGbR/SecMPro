// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 FZ-01: the backup import decoder (`secmp_store::backup`, ADR-053 item 6 and Appendix) on arbitrary
//! bytes, with a fixed passphrase and the `kat` Argon2 parameters, no file I/O per input: never panics, and accepts only
//! a decryptable, well-formed export.
//!
//! Input: `mode u8 ‖ rest`.
//! - Even mode: `rest` is a whole file for `backup::open_export_kat`. It opens only if the bytes are an export sealed
//!   under the passphrase (a seed may be one); then its contents re-encode to its decrypted body.
//! - Odd mode: `rest = l1 u16 ‖ l2 u16 ‖ l3 u16 ‖ body`. The harness seals `body` honestly (`backup::seal_file_kat`)
//!   with the section table `{1, l1} {2, l2} {3, l3} {4, rest of body}` (lengths clamped to the body), which reaches the
//!   section decoders. It opens iff the four sections decode; then the contents re-encode to exactly `body` (the
//!   decoder is canonical), and the same file with one byte changed is refused with the one uniform `Err(Unlock)`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_store::Error;
use secmp_store::backup::{encode_body_kat, open_body_kat, open_export_kat, seal_file_kat};

/// The fixed backup passphrase of the target.
const PASS: &[u8] = b"fuzz backup passphrase";

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        if let Ok(contents) = open_export_kat(rest, PASS) {
            let body = open_body_kat(rest, PASS).ok();
            let again = encode_body_kat(&contents).ok();
            assert!(body.is_some() && body.as_deref() == again.as_deref(), "an accepted file re-encodes to its body");
        }
        return;
    }
    let Some((lens, body)) = rest.split_first_chunk::<6>() else {
        return;
    };
    let mut table = Vec::with_capacity(4);
    let mut left = body.len();
    for (tag, l) in [1_u8, 2, 3].into_iter().zip(lens.chunks(2)) {
        let want = l.iter().fold(0_usize, |n, b| n.wrapping_mul(256).wrapping_add(usize::from(*b)));
        let take = want.min(left);
        left -= take;
        table.push((tag, u32::try_from(take).unwrap_or(u32::MAX)));
    }
    table.push((4, u32::try_from(left).unwrap_or(u32::MAX)));
    let Ok(file) = seal_file_kat(PASS, &table, body) else {
        return;
    };
    match open_export_kat(&file, PASS) {
        Ok(contents) => {
            let again = encode_body_kat(&contents).ok();
            assert_eq!(again.as_deref().map(Vec::as_slice), Some(body), "the decoder is canonical");
            let at = usize::from(lens.first().copied().unwrap_or(0)).wrapping_mul(31) % file.len();
            let mut bad = file;
            if let Some(b) = bad.get_mut(at) {
                *b ^= 1;
            }
            assert_eq!(open_export_kat(&bad, PASS).err(), Some(Error::Unlock));
        }
        Err(e) => assert_eq!(e, Error::Unlock, "every refusal is the one uniform error"),
    }
});
