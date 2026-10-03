// SPDX-License-Identifier: AGPL-3.0-or-later
//! SHA-256 (FIPS 180-4) of file contents, for the hashes `expect.rs` pins (M4 review C-7, ADR-046 Amendment 1: the
//! ProVerif models). Build tooling only: xtask has no cryptographic dependency (ADR-031), the digest compares a file
//! with the reviewed content and protects no secret, and it is checked against the FIPS 180-2 examples below.

/// The round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The message schedule of one 64-byte block (FIPS 180-4 §6.2.2 step 1).
fn schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0_u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for t in 16_usize..64 {
        let at = |k: usize| w.get(t.wrapping_sub(k)).copied().unwrap_or(0);
        let (w2, w7, w15, w16) = (at(2), at(7), at(15), at(16));
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        if let Some(slot) = w.get_mut(t) {
            *slot = s1.wrapping_add(w7).wrapping_add(s0).wrapping_add(w16);
        }
    }
    w
}

/// The SHA-256 digest of `data`.
pub(crate) fn digest(data: &[u8]) -> [u8; 32] {
    let bits = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() & 63 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    let mut state = H0;
    for block in msg.as_chunks::<64>().0 {
        let words = schedule(block);
        // the working variables a … h of FIPS 180-4 §6.2.2
        let [
            mut va,
            mut vb,
            mut vc,
            mut vd,
            mut ve,
            mut vf,
            mut vg,
            mut vh,
        ] = state;
        for (k, wt) in K.iter().zip(words.iter()) {
            let s1 = ve.rotate_right(6) ^ ve.rotate_right(11) ^ ve.rotate_right(25);
            let ch = (ve & vf) ^ (!ve & vg);
            let t1 = vh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*k)
                .wrapping_add(*wt);
            let s0 = va.rotate_right(2) ^ va.rotate_right(13) ^ va.rotate_right(22);
            let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
            let t2 = s0.wrapping_add(maj);
            vh = vg;
            vg = vf;
            vf = ve;
            ve = vd.wrapping_add(t1);
            vd = vc;
            vc = vb;
            vb = va;
            va = t1.wrapping_add(t2);
        }
        for (x, y) in state.iter_mut().zip([va, vb, vc, vd, ve, vf, vg, vh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0_u8; 32];
    for (o, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *o = word.to_be_bytes();
    }
    out
}

/// The digest of `data` in lower-case hex.
pub(crate) fn hex(data: &[u8]) -> String {
    digest(data).iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The hex digest of a text file as the repository holds it: CRLF line ends (a Windows checkout with `core.autocrlf`)
/// are read as LF, so the digest is the one `sha256sum` gives on the committed content. `None` if unreadable.
pub(crate) fn text_file_hex(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut lf = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter().peekable();
    while let Some(b) = it.next() {
        if *b == b'\r' && it.peek() == Some(&&b'\n') {
            continue;
        }
        lf.push(*b);
    }
    Some(hex(&lf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-2 Appendix B: "abc", the two-block 448-bit message, one million "a"; and the empty message.
    #[test]
    fn fips_180_examples() {
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // 55, 56 and 64 bytes: the padding boundaries
        assert_eq!(
            hex(&[b'a'; 55]),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            hex(&[b'a'; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }

    /// A CRLF checkout hashes like the LF content; a lone CR is content.
    #[test]
    fn crlf_reads_as_lf() -> std::io::Result<()> {
        let dir = std::env::temp_dir().join(format!("secmp-xtask-sha256-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("lf"), b"a\nb\n")?;
        std::fs::write(dir.join("crlf"), b"a\r\nb\r\n")?;
        std::fs::write(dir.join("cr"), b"a\rb\n")?;
        let lf = text_file_hex(&dir.join("lf"));
        assert_eq!(lf, Some(hex(b"a\nb\n")));
        assert_eq!(text_file_hex(&dir.join("crlf")), lf);
        assert_ne!(text_file_hex(&dir.join("cr")), lf);
        assert_eq!(text_file_hex(&dir.join("missing")), None);
        std::fs::remove_dir_all(&dir)
    }
}
