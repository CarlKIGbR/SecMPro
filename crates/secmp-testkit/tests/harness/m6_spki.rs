// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's pin (`secmp_relay::spki`, what `secmp-relay spki` prints, TLS-15) and the client's pin check
//! (`secmp_transport::tls`, fuzzed as FZ-02) read the `SubjectPublicKeyInfo` with two copies of one DER walk (the relay
//! may not depend on the transport crate, `docs/02` §3). They must agree on every input, or a relay would print a pin
//! that its clients refuse (or accept a certificate they should not).

use secmp_testkit::harness::cert::{EXPIRED, FixtureKey, VALID, certificate, self_signed};

/// Deterministic mutations (xorshift64*; not cryptographic).
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next().checked_rem(u64::try_from(n).unwrap()).unwrap()).unwrap()
    }
}

fn agree(input: &[u8]) {
    let relay = secmp_relay::spki::spki_of(input);
    let client = secmp_transport::tls::spki_of(input);
    assert_eq!(relay, client, "{input:02x?}");
    let pin = relay.map_or([0; 32], |s| secmp_crypto::sha256(&[s]));
    assert_eq!(secmp_relay::spki::pin_of(input), relay.map(|_| pin));
    if relay.is_some() {
        assert!(secmp_transport::tls::check_pin(input, 0, &pin).is_ok());
    }
}

/// The two walks agree on certificates, their truncations, and 20 000 seeded byte mutations (flips, insertions,
/// deletions, length-byte edits); the relay's pin of a fixture certificate is the fixture key's pin.
#[test]
fn relay_and_client_spki_walks_agree() {
    let issuer = FixtureKey::new([0x31; 32]);
    let certs: Vec<Vec<u8>> = (0_u8..6)
        .map(|n| {
            let k = FixtureKey::new([n; 32]);
            match n % 3 {
                0 => self_signed(&k, "relay.test", VALID),
                1 => certificate(&k, "a.example", &issuer, "ca", EXPIRED, n == 4, n),
                _ => self_signed(&k, &"x".repeat(usize::from(n) * 60), VALID),
            }
        })
        .collect();
    for (n, c) in certs.iter().enumerate() {
        let k = FixtureKey::new([u8::try_from(n).unwrap(); 32]);
        assert_eq!(secmp_relay::spki::pin_of(c), Some(k.pin()));
        for end in 0..=c.len() {
            agree(c.get(..end).unwrap());
        }
    }
    let mut mix = Mix(0x5ec0_0002);
    for _ in 0..20_000 {
        let mut c = certs.get(mix.below(certs.len())).unwrap().clone();
        for _ in 0..=mix.below(3) {
            let at = mix.below(c.len());
            match mix.below(4) {
                0 => *c.get_mut(at).unwrap() ^= 1 << mix.below(8),
                1 => c.insert(at, u8::try_from(mix.below(256)).unwrap()),
                2 => {
                    c.remove(at);
                }
                _ => {
                    let edge = [0x00, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0xff];
                    *c.get_mut(at).unwrap() = edge.get(mix.below(8)).copied().unwrap();
                }
            }
            if c.is_empty() {
                break;
            }
        }
        agree(&c);
    }
}
