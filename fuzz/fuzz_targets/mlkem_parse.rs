// SPDX-License-Identifier: AGPL-3.0-or-later
//! ML-KEM-768/1024 parsing and use on arbitrary bytes: never panics. The first byte selects the object:
//! encapsulation keys (validated import; an imported key re-encodes to its input and encapsulates), ciphertexts
//! (length-checked; decapsulation under a fixed key is deterministic, FIPS 203 implicit rejection), and seeds
//! (a key from any 64-byte seed round-trips).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use secmp_crypto::{Error, MlKem768Ct, MlKem768Dk, MlKem768Ek, MlKem1024Ct, MlKem1024Dk, MlKem1024Ek};

/// Plain equality of two exposed secrets (constant time is not what this target tests).
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a == b
}

fn dk768() -> Option<&'static MlKem768Dk> {
    static K: OnceLock<Option<MlKem768Dk>> = OnceLock::new();
    K.get_or_init(|| MlKem768Dk::from_seed(&[1; 64]).ok()).as_ref()
}

fn dk1024() -> Option<&'static MlKem1024Dk> {
    static K: OnceLock<Option<MlKem1024Dk>> = OnceLock::new();
    K.get_or_init(|| MlKem1024Dk::from_seed(&[2; 64]).ok()).as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 6 {
        0 => {
            if let Ok(ek) = MlKem768Ek::from_bytes(rest) {
                assert_eq!(ek.as_bytes().as_slice(), rest);
                assert!(ek.encapsulate().is_ok());
            }
        }
        1 => {
            if let Ok(ek) = MlKem1024Ek::from_bytes(rest) {
                assert_eq!(ek.as_bytes().as_slice(), rest);
                assert!(ek.encapsulate().is_ok());
            }
        }
        2 => match (MlKem768Ct::from_bytes(rest), dk768()) {
            (Ok(ct), Some(dk)) => {
                let a = dk.decapsulate(&ct);
                let b = dk.decapsulate(&ct);
                assert!(same(a.expose_secret(), b.expose_secret()));
            }
            (Err(e), _) => assert_eq!(e, Error::Rejected),
            _ => {}
        },
        3 => match (MlKem1024Ct::from_bytes(rest), dk1024()) {
            (Ok(ct), Some(dk)) => {
                let a = dk.decapsulate(&ct);
                let b = dk.decapsulate(&ct);
                assert!(same(a.expose_secret(), b.expose_secret()));
            }
            (Err(e), _) => assert_eq!(e, Error::Rejected),
            _ => {}
        },
        4 => {
            if let Ok(dk) = MlKem768Dk::from_seed(rest) {
                let ek = dk.encapsulation_key();
                assert!(MlKem768Ek::from_bytes(ek.as_bytes()).is_ok());
                if let Ok((ct, ss)) = ek.encapsulate() {
                    assert!(same(dk.decapsulate(&ct).expose_secret(), ss.expose_secret()));
                }
            }
        }
        _ => {
            if let Ok(dk) = MlKem1024Dk::from_seed(rest) {
                let ek = dk.encapsulation_key();
                assert!(MlKem1024Ek::from_bytes(ek.as_bytes()).is_ok());
                if let Ok((ct, ss)) = ek.encapsulate() {
                    assert!(same(dk.decapsulate(&ct).expose_secret(), ss.expose_secret()));
                }
            }
        }
    }
});
