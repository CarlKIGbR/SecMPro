// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz inputs derived from the frozen SecMP vectors (M2 review F7): the seeding step of the `fuzz` gate and of the
//! nightly campaign writes them into the scratch corpus `target/fuzz-corpus/<target>/` before libFuzzer starts, next
//! to the tracked corpus `fuzz/corpus/<target>/` (read-only for the gates).
//!
//! [`SEED_RULES`] is keyed by fuzz target: each rule names a frozen suite (`vectors/<suite>.json`, one of
//! `expect::VECTOR_SUITES`) and a function that turns one case of it into inputs **in the target's input layout**
//! (its mode or selector byte and its split fields, as documented in the target's header comment). A target may have
//! several rules; a target without a rule relies on its tracked corpus alone. To seed a new target, add its rules
//! here (the unit tests require every rule to name a listed target and a frozen suite, and every seed to fit the
//! target's `-max_len`).
//!
//! | target | suite | inputs per case |
//! |---|---|---|
//! | `msg_open` | `msgencrypt` | `seal`: mode 1 ‖ `ad_len` ‖ `ad` ‖ `p` (seal, open, flip), and mode 0 ‖ … ‖ `c_tag` (open under the fixed key); `open`: mode 0 ‖ `ad_len` ‖ `ad` ‖ `c_tag` (an AD above 255 bytes is cut to 255) |
//! | `caead_open` | `caead` | `seal`: mode 1 ‖ `n` ‖ `ad_len` ‖ `ad` ‖ `p`, and mode 0 ‖ `n` ‖ `ad_len` ‖ `ad` ‖ `com` ‖ `c`; `open`: mode 0 ‖ … ‖ `com` ‖ `c` |
//! | `mlkem_parse` | `hybridkem-768`, `hybridkem-1024` | every `ek_kem`, `ct_kem` and `dk_seed` of a case behind its mode byte (768: 0, 2, 4; 1024: 1, 3, 5) |
//! | `x25519_dh` | `hybridkem-768`, `hybridkem-1024` | the case's first and last X25519 secret (`sk_e`, `sk_dh`) ‖ each of its public keys (`pk_dh`, `pk_e`) |
//! | `ed25519_verify` | `hybridsign` | `pk_ed` ‖ the Ed25519 half of `sig` ‖ `msg`; for `sign` also `ed_seed` ‖ … (the honest-key branch) |
//! | `hybrid_sign_verify` | `hybridsign` | mode 0 ‖ label 0 ‖ `pk_ed` ‖ `pk_mldsa`; mode 1 ‖ label 0 ‖ `sig` ‖ `msg`; for `sign` also mode 2 ‖ label 0 ‖ `msg` |
//! | `mldsa65_verify` | `hybridsign` | mode 0 ‖ `pk_mldsa`; mode 1 ‖ `ctx_len` 0 ‖ the ML-DSA half of `sig` |
//! | `proto_records`, `proto_frames`, `proto_invitation`, `proto_handshake`, `proto_cell` | `encodings` | every decodable row (positive: `outputs.bytes`, negative: `inputs.bytes`) as selector ‖ bytes in the target of its structure ([`encodings_target`]); the encode-only `Signed/*` rows have no decoder |
//! | `tr_decrypt` | `tr` | the `cell` of every `send` case (`outputs`) and `recv-reject` case (`inputs`, incl. the 4095- and 4097-byte ones) as mode 0 ‖ cell (they are sealed under the vector session's keys: the fixed receiver of the target rejects them) |
//! | `tr_state` | `tr` | the `init` case: selector 0 ‖ a `RatchetStateV1` of the §7.2 responder's shape filled with the case's bytes ([`tr_state`]) |
//!
//! The label byte of `hybrid_sign_verify` is 0 for every seed: the target picks `Label::ALL[byte % len]`, and its
//! verification seeds are rejected under its fixed key whatever the label; the fuzzer varies the byte.

use std::path::Path;

use serde_json::Value;

use crate::expect;
use crate::util::{Error, Result, bail};

/// One input for a fuzz target: a file name (unique within the target) and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seed {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}

/// The inputs one vector case gives a target (empty if the case has nothing in the target's layout).
type SeedFn = fn(&Value) -> Result<Vec<(&'static str, Vec<u8>)>>;

/// One seeding rule: the target, the frozen suite it reads, and the case → inputs function.
pub(crate) struct SeedRule {
    pub(crate) target: &'static str,
    pub(crate) suite: &'static str,
    seeds: SeedFn,
}

/// The seeding table, keyed by fuzz target (module documentation).
pub(crate) const SEED_RULES: &[SeedRule] = &[
    SeedRule {
        target: "caead_open",
        suite: "caead",
        seeds: caead_open,
    },
    SeedRule {
        target: "ed25519_verify",
        suite: "hybridsign",
        seeds: ed25519_verify,
    },
    SeedRule {
        target: "hybrid_sign_verify",
        suite: "hybridsign",
        seeds: hybrid_sign_verify,
    },
    SeedRule {
        target: "mldsa65_verify",
        suite: "hybridsign",
        seeds: mldsa65_verify,
    },
    SeedRule {
        target: "mlkem_parse",
        suite: "hybridkem-768",
        seeds: mlkem_parse_768,
    },
    SeedRule {
        target: "mlkem_parse",
        suite: "hybridkem-1024",
        seeds: mlkem_parse_1024,
    },
    SeedRule {
        target: "msg_open",
        suite: "msgencrypt",
        seeds: msg_open,
    },
    SeedRule {
        target: "proto_cell",
        suite: "encodings",
        seeds: proto_cell,
    },
    SeedRule {
        target: "proto_frames",
        suite: "encodings",
        seeds: proto_frames,
    },
    SeedRule {
        target: "proto_handshake",
        suite: "encodings",
        seeds: proto_handshake,
    },
    SeedRule {
        target: "proto_invitation",
        suite: "encodings",
        seeds: proto_invitation,
    },
    SeedRule {
        target: "proto_records",
        suite: "encodings",
        seeds: proto_records,
    },
    SeedRule {
        target: "tr_decrypt",
        suite: "tr",
        seeds: tr_decrypt,
    },
    SeedRule {
        target: "tr_state",
        suite: "tr",
        seeds: tr_state,
    },
    SeedRule {
        target: "x25519_dh",
        suite: "hybridkem-768",
        seeds: x25519_dh,
    },
    SeedRule {
        target: "x25519_dh",
        suite: "hybridkem-1024",
        seeds: x25519_dh,
    },
];

/// Lowercase hex (SCHEMA §1) to bytes.
fn unhex(s: &str) -> Result<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => Err(Error(format!("not lowercase hex: {s:?}"))),
    };
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex: {s:?}");
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Ok(digit(*hi)?.wrapping_shl(4) | digit(*lo)?))
        .collect()
}

/// The byte string `key` of a case, from its inputs or else its outputs.
fn field(case: &Value, key: &str) -> Result<Option<Vec<u8>>> {
    ["inputs", "outputs"]
        .iter()
        .find_map(|section| case.get(section).and_then(|s| s.get(key)))
        .and_then(Value::as_str)
        .map(unhex)
        .transpose()
}

fn op(case: &Value) -> &str {
    case.get("op").and_then(Value::as_str).unwrap_or_default()
}

/// `[a] ‖ b ‖ …`
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `ad_len u8 ‖ ad`, the AD cut to the targets' one-byte length (255 bytes): the body is what the seed is for, and
/// the targets reject a body sealed under another AD (mode 0) or seal and open it themselves (mode 1).
fn ad_prefixed(ad: &[u8]) -> Vec<u8> {
    let ad = ad.get(..255).unwrap_or(ad);
    cat(&[&[u8::try_from(ad.len()).unwrap_or(u8::MAX)], ad])
}

/// `msg_open`: mode ‖ `ad_len` ‖ AD ‖ body.
fn msg_open(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let ad = ad_prefixed(&field(case, "ad")?.unwrap_or_default());
    let mut out = Vec::new();
    if let Some(p) = field(case, "p")? {
        out.push(("seal", cat(&[&[1], &ad, &p])));
    }
    if let Some(c_tag) = field(case, "c_tag")? {
        out.push((op_label(case), cat(&[&[0], &ad, &c_tag])));
    }
    Ok(out)
}

/// `caead_open`: mode ‖ nonce (24) ‖ `ad_len` ‖ AD ‖ body.
fn caead_open(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let Some(n) = field(case, "n")?.filter(|n| n.len() == 24) else {
        return Ok(Vec::new());
    };
    let ad = ad_prefixed(&field(case, "ad")?.unwrap_or_default());
    let mut out = Vec::new();
    if let Some(p) = field(case, "p")? {
        out.push(("seal", cat(&[&[1], &n, &ad, &p])));
    }
    if let (Some(com), Some(c)) = (field(case, "com")?, field(case, "c")?) {
        out.push((op_label(case), cat(&[&[0], &n, &ad, &com, &c])));
    }
    Ok(out)
}

/// `open` for an `open` case, `sealed` for the output of a `seal` case.
fn op_label(case: &Value) -> &'static str {
    if op(case) == "open" { "open" } else { "sealed" }
}

/// `mlkem_parse`: mode ‖ object, with the modes (ek, ct, seed) of one parameter set.
fn mlkem_parse(case: &Value, modes: [u8; 3]) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let mut out = Vec::new();
    for ((key, label), mode) in [("ek_kem", "ek"), ("ct_kem", "ct"), ("dk_seed", "seed")]
        .into_iter()
        .zip(modes)
    {
        if let Some(bytes) = field(case, key)? {
            out.push((label, cat(&[&[mode], &bytes])));
        }
    }
    Ok(out)
}

fn mlkem_parse_768(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    mlkem_parse(case, [0, 2, 4])
}

fn mlkem_parse_1024(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    mlkem_parse(case, [1, 3, 5])
}

/// `x25519_dh`: secret ‖ secret ‖ public key, 32 bytes each.
fn x25519_dh(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let secrets: Vec<Vec<u8>> = ["sk_e", "sk_dh"]
        .into_iter()
        .map(|k| field(case, k))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .filter(|s| s.len() == 32)
        .collect();
    let (Some(a), Some(b)) = (secrets.first(), secrets.last()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (key, label) in [("pk_dh", "pk_dh"), ("pk_e", "pk_e")] {
        if let Some(pk) = field(case, key)?.filter(|pk| pk.len() == 32) {
            out.push((label, cat(&[a, b, &pk])));
        }
    }
    Ok(out)
}

/// The Ed25519 half (bytes 0..64) and the ML-DSA-65 half of a `HybridSig`.
fn split_sig(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    (sig.len() > 64).then(|| sig.split_at(64))
}

/// `ed25519_verify`: key or seed (32) ‖ signature (64) ‖ message.
fn ed25519_verify(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let (Some(sig), msg) = (field(case, "sig")?, field(case, "msg")?.unwrap_or_default()) else {
        return Ok(Vec::new());
    };
    let Some((ed_sig, _)) = split_sig(&sig) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (key, label) in [("pk_ed", "pk"), ("ed_seed", "seed")] {
        if let Some(k) = field(case, key)?.filter(|k| k.len() == 32) {
            out.push((label, cat(&[&k, ed_sig, &msg])));
        }
    }
    Ok(out)
}

/// `hybrid_sign_verify`: mode ‖ label byte ‖ rest.
fn hybrid_sign_verify(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let msg = field(case, "msg")?.unwrap_or_default();
    let mut out = Vec::new();
    if let (Some(ed), Some(mldsa)) = (field(case, "pk_ed")?, field(case, "pk_mldsa")?) {
        out.push(("import", cat(&[&[0, 0], &ed, &mldsa])));
    }
    if let Some(sig) = field(case, "sig")? {
        out.push(("verify", cat(&[&[1, 0], &sig, &msg])));
    }
    if op(case) == "sign" {
        out.push(("sign", cat(&[&[2, 0], &msg])));
    }
    Ok(out)
}

/// `mldsa65_verify`: mode 0 ‖ key; mode 1 ‖ `ctx_len` ‖ context ‖ signature.
fn mldsa65_verify(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let mut out = Vec::new();
    if let Some(pk) = field(case, "pk_mldsa")? {
        out.push(("import", cat(&[&[0], &pk])));
    }
    if let Some(sig) = field(case, "sig")?
        && let Some((_, mldsa_sig)) = split_sig(&sig)
    {
        out.push(("verify", cat(&[&[1, 0], mldsa_sig])));
    }
    Ok(out)
}

/// The fuzz target and selector byte of an `encodings` structure (the selector order is the one in each `proto_*`
/// target's header comment; `Response/*` rows other than `CELLR` decode in any context and go to `FETCH`'s).
/// `Ok(None)` for the encode-only `Signed/*` rows; an unknown structure is refused, so a new structure needs an
/// entry here.
pub(crate) fn encodings_target(
    structure: &str,
    context: Option<&str>,
) -> Result<Option<(&'static str, u8)>> {
    const TABLE: &[(&str, &str, u8)] = &[
        ("Record/HELLO", "proto_records", 0),
        ("Record/RELAYINFO", "proto_records", 1),
        ("Record/HS1", "proto_records", 2),
        ("Record/HS2", "proto_records", 3),
        ("RelayInfoV1", "proto_records", 4),
        ("RelayRef", "proto_invitation", 0),
        ("InvitationV1", "proto_invitation", 1),
        ("Profile", "proto_invitation", 2),
        ("LinkDataV1", "proto_invitation", 3),
        ("LinkBlob", "proto_invitation", 4),
        ("IKSPublic", "proto_invitation", 5),
        ("PrekeyBundle", "proto_invitation", 6),
        ("Outer", "proto_handshake", 0),
        ("inner_ct", "proto_handshake", 1),
        ("Inner", "proto_handshake", 2),
        ("HandshakeCell", "proto_handshake", 3),
        ("HandshakeCellPlaintext", "proto_handshake", 4),
        ("Cell", "proto_cell", 0),
        ("HeaderV1", "proto_cell", 1),
        ("Content", "proto_cell", 2),
        ("AppMessage", "proto_cell", 3),
        ("BatchBody", "proto_cell", 4),
        ("Fragment", "proto_cell", 5),
        ("FragmentPayload", "proto_cell", 6),
        ("RouteDescriptor", "proto_cell", 7),
        ("RelayQueue", "proto_cell", 8),
        ("RouteUpdateBody", "proto_cell", 9),
        ("HandshakeBody", "proto_cell", 10),
        ("KeyChangeBody", "proto_cell", 11),
        ("ReceiptBody", "proto_cell", 12),
        ("ControlBody", "proto_cell", 13),
    ];
    if structure.starts_with("Signed/") {
        return Ok(None);
    }
    if structure.starts_with("Request/") {
        return Ok(Some(("proto_frames", 0)));
    }
    if structure == "Response/CELLR" {
        return match context {
            Some("FETCH") => Ok(Some(("proto_frames", 1))),
            Some("FETCH_MULTI") => Ok(Some(("proto_frames", 2))),
            other => bail!("encodings: Response/CELLR with context {other:?}"),
        };
    }
    if structure.starts_with("Response/") {
        return Ok(Some(("proto_frames", 1)));
    }
    TABLE
        .iter()
        .find(|(s, _, _)| *s == structure)
        .map(|(_, t, sel)| Some((*t, *sel)))
        .ok_or_else(|| {
            Error(format!(
                "encodings: structure {structure:?} has no fuzz target (xtask/src/fuzzseed.rs)"
            ))
        })
}

/// The `encodings` row as selector ‖ bytes, if its structure belongs to `target`.
fn encodings_seed(target: &str, case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let inputs = case.get("inputs");
    let structure = inputs
        .and_then(|i| i.get("structure"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let context = inputs
        .and_then(|i| i.get("context"))
        .and_then(Value::as_str);
    let Some((t, selector)) = encodings_target(structure, context)? else {
        return Ok(Vec::new());
    };
    if t != target {
        return Ok(Vec::new());
    }
    let (label, key) = if op(case) == "encode" {
        ("positive", "outputs")
    } else {
        ("negative", "inputs")
    };
    let Some(hex) = case
        .get(key)
        .and_then(|s| s.get("bytes"))
        .and_then(Value::as_str)
    else {
        bail!(
            "encodings: row {} has no {key}.bytes",
            case.get("id").and_then(Value::as_str).unwrap_or("?")
        );
    };
    Ok(vec![(label, cat(&[&[selector], &unhex(hex)?]))])
}

fn proto_records(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    encodings_seed("proto_records", case)
}

fn proto_frames(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    encodings_seed("proto_frames", case)
}

fn proto_invitation(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    encodings_seed("proto_invitation", case)
}

fn proto_handshake(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    encodings_seed("proto_handshake", case)
}

fn proto_cell(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    encodings_seed("proto_cell", case)
}

/// `tr_decrypt`: mode 0 ‖ the case's `cell` (a `send` case's output, a `recv-reject` case's input), any length.
fn tr_decrypt(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    Ok(field(case, "cell")?
        .map(|cell| vec![("cell", cat(&[&[0], &cell]))])
        .unwrap_or_default())
}

/// `tr_state`, from the `init` case: selector 0 ‖ `RatchetStateV1` (`secmp-proto` `tr/state.rs`) in the shape of
/// the §7.2 responder — `sb`, `rk`, `dh_s.sk` = `spk_dh_sk`, no `dh_r`, `kem_s.seed` = `rpk_kem_seed`, no
/// `kem_r`/`last_ct_r`/`ct_s`, no chain or header keys but `nhk_s` and `nhk_r`, counters 0, no skipped keys. xtask
/// computes no HKDF, so the three derived keys `rk`, `nhk_s`, `nhk_r` are filled with the case's `sk`, `m` and
/// `dh_s_sk` (the decoder checks the shape, not the derivation): an input the decoder accepts, which the fuzzer
/// mutates from there.
fn tr_state(case: &Value) -> Result<Vec<(&'static str, Vec<u8>)>> {
    let get = |key: &str, len: usize| -> Result<Option<Vec<u8>>> {
        Ok(field(case, key)?.filter(|v| v.len() == len))
    };
    let (Some(sb), Some(sk), Some(spk), Some(seed), Some(m), Some(dh)) = (
        get("sb", 32)?,
        get("sk", 32)?,
        get("spk_dh_sk", 32)?,
        get("rpk_kem_seed", 64)?,
        get("m", 32)?,
        get("dh_s_sk", 32)?,
    ) else {
        return Ok(Vec::new());
    };
    // fmt, then: dh_r absent; kem_r, last_ct_r, ct_s absent; ck_s, ck_r, hk_s, hk_r absent; nhk_s, nhk_r present;
    // n_s, n_r, pn = 0; count = 0
    Ok(vec![(
        "responder-state",
        cat(&[
            &[0, 1],
            &sb,
            &sk,
            &spk,
            &[0],
            &seed,
            &[0, 0, 0, 0, 0, 0, 0, 1],
            &m,
            &[1],
            &dh,
            &[0; 14],
        ]),
    )])
}

/// The seeds of `target` from the frozen suites, read through `read_suite` (the parsed `vectors/<suite>.json`).
/// Names are `<suite>-<case id>-<what>`; a case whose fields do not fit the target's layout gives no seed. A seed
/// longer than the target's `-max_len` is cut to it (libFuzzer reads no more of a corpus file; the long messages of
/// some `hybridsign` cases exceed the largest Ed25519-signed message of the protocol).
pub(crate) fn seeds_for(
    target: &str,
    read_suite: &dyn Fn(&str) -> Result<Value>,
) -> Result<Vec<Seed>> {
    let max_len = crate::gates::fuzz_max_len(target)?;
    let mut out = Vec::new();
    for rule in SEED_RULES.iter().filter(|r| r.target == target) {
        if !expect::VECTOR_SUITES.contains(&rule.suite) {
            bail!(
                "fuzz seeding: {target} reads {}, which is not a frozen suite",
                rule.suite
            );
        }
        let doc = read_suite(rule.suite)?;
        let cases = doc
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| Error(format!("vectors/{}.json: no cases", rule.suite)))?;
        for case in cases {
            let id = case.get("id").and_then(Value::as_str).unwrap_or("?");
            for (what, mut bytes) in (rule.seeds)(case)? {
                bytes.truncate(max_len);
                out.push(Seed {
                    name: format!("{}-{id}-{what}", rule.suite),
                    bytes,
                });
            }
        }
    }
    Ok(out)
}

/// The seeding step: `target/fuzz-corpus/<target>/` is deleted, created afresh and filled with the vector seeds of
/// `target`. Returns the number of seeds written.
pub(crate) fn seed_scratch_corpus(root: &Path, target: &str) -> Result<usize> {
    let dir = root.join("target").join("fuzz-corpus").join(target);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    let read = |suite: &str| -> Result<Value> {
        let path = root.join("vectors").join(format!("{suite}.json"));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&text).map_err(|e| Error(format!("{}: {e}", path.display())))
    };
    let seeds = seeds_for(target, &read)?;
    for s in &seeds {
        std::fs::write(dir.join(&s.name), &s.bytes)?;
    }
    Ok(seeds.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frozen(suite: &str) -> Result<Value> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("vectors")
            .join(format!("{suite}.json"));
        let text = std::fs::read_to_string(&path).map_err(|e| Error(e.to_string()))?;
        serde_json::from_str(&text).map_err(|e| Error(e.to_string()))
    }

    /// Every rule names a listed fuzz target and a frozen suite; every listed target is seeded.
    #[test]
    fn the_rules_name_listed_targets_and_frozen_suites() {
        for r in SEED_RULES {
            assert!(expect::FUZZ_TARGETS.contains(&r.target), "{}", r.target);
            assert!(expect::VECTOR_SUITES.contains(&r.suite), "{}", r.suite);
        }
        for t in expect::FUZZ_TARGETS {
            assert!(
                SEED_RULES.iter().any(|r| r.target == *t),
                "{t} has no seeding rule"
            );
        }
    }

    /// The frozen vectors seed every target, each seed within the target's `-max_len`, names unique per target; the
    /// counts are pinned so that a rule that silently stops producing seeds fails here.
    #[test]
    fn the_frozen_vectors_seed_every_target() -> Result<()> {
        let expected: &[(&str, usize)] = &[
            ("caead_open", 25),
            ("ed25519_verify", 25),
            ("hybrid_sign_verify", 42),
            ("mldsa65_verify", 34),
            ("mlkem_parse", 86),
            ("msg_open", 24),
            ("proto_cell", 190),
            ("proto_frames", 182),
            ("proto_handshake", 40),
            ("proto_invitation", 132),
            ("proto_records", 81),
            // 40 `send` cells and 13 `recv-reject` cells; one state from the `init` case
            ("tr_decrypt", 53),
            ("tr_state", 1),
            ("x25519_dh", 54),
        ];
        let mut total_proto = 0_usize;
        for (t, n) in expected {
            let seeds = seeds_for(t, &frozen)?;
            let max_len = expect::FUZZ_MAX_LEN
                .iter()
                .find(|(name, _)| name == t)
                .map_or(0, |(_, m)| *m);
            for s in &seeds {
                assert!(
                    s.bytes.len() <= max_len,
                    "{t} {}: {} > {max_len}",
                    s.name,
                    s.bytes.len()
                );
            }
            let names: std::collections::BTreeSet<&str> =
                seeds.iter().map(|s| s.name.as_str()).collect();
            assert_eq!(names.len(), seeds.len(), "{t}: duplicate names");
            assert_eq!(seeds.len(), *n, "{t}");
            if t.starts_with("proto_") {
                total_proto = total_proto.saturating_add(seeds.len());
            }
        }
        assert_eq!(expected.len(), expect::FUZZ_TARGETS.len());
        // every decodable `encodings` row, once: 78 positives and 547 negatives
        assert_eq!(total_proto, 625);
        Ok(())
    }

    /// The layouts, on the first case of each kind.
    #[test]
    fn seeds_follow_the_target_layouts() -> Result<()> {
        let case = serde_json::json!({"id": "x", "op": "seal",
            "inputs": {"mk": "00", "ad": "aabb", "p": "0102", "k": "00", "n": "11".repeat(24)},
            "outputs": {"c_tag": "0304", "com": "05", "c": "06"}});
        assert_eq!(
            msg_open(&case)?,
            vec![
                ("seal", vec![1, 2, 0xaa, 0xbb, 1, 2]),
                ("sealed", vec![0, 2, 0xaa, 0xbb, 3, 4])
            ]
        );
        let nonce = vec![0x11_u8; 24];
        assert_eq!(
            caead_open(&case)?,
            vec![
                ("seal", cat(&[&[1], &nonce, &[2, 0xaa, 0xbb, 1, 2]])),
                ("sealed", cat(&[&[0], &nonce, &[2, 0xaa, 0xbb, 5, 6]]))
            ]
        );
        // an AD longer than the one-byte length is cut to 255 bytes
        let long = serde_json::json!({"id": "x", "op": "open",
            "inputs": {"ad": "00".repeat(256), "c_tag": "01"}});
        assert_eq!(
            msg_open(&long)?,
            vec![("open", cat(&[&[0, 255], &[0; 255], &[1]]))]
        );
        let kem = serde_json::json!({"id": "x", "op": "encaps",
            "inputs": {"dk_seed": "07", "sk_e": "01".repeat(32), "sk_dh": "02".repeat(32)},
            "outputs": {"ek_kem": "08", "ct_kem": "09", "pk_dh": "03".repeat(32), "pk_e": "04".repeat(32)}});
        assert_eq!(
            mlkem_parse_1024(&kem)?,
            vec![("ek", vec![1, 8]), ("ct", vec![3, 9]), ("seed", vec![5, 7])]
        );
        let dh = x25519_dh(&kem)?;
        assert_eq!(dh.len(), 2);
        assert_eq!(
            dh.first().map(|(_, b)| b.clone()),
            Some(cat(&[&[1; 32], &[2; 32], &[3; 32]]))
        );
        let sign = serde_json::json!({"id": "x", "op": "sign",
            "inputs": {"ed_seed": "05".repeat(32), "msg": "abcd"},
            "outputs": {"pk_ed": "06".repeat(32), "pk_mldsa": "0708", "sig": "09".repeat(66)}});
        assert_eq!(
            ed25519_verify(&sign)?,
            vec![
                ("pk", cat(&[&[6; 32], &[9; 64], &[0xab, 0xcd]])),
                ("seed", cat(&[&[5; 32], &[9; 64], &[0xab, 0xcd]]))
            ]
        );
        assert_eq!(
            hybrid_sign_verify(&sign)?,
            vec![
                ("import", cat(&[&[0, 0], &[6; 32], &[7, 8]])),
                ("verify", cat(&[&[1, 0], &[9; 66], &[0xab, 0xcd]])),
                ("sign", vec![2, 0, 0xab, 0xcd])
            ]
        );
        assert_eq!(
            mldsa65_verify(&sign)?,
            vec![("import", vec![0, 7, 8]), ("verify", vec![1, 0, 9, 9])]
        );
        let send = serde_json::json!({"id": "tr-0002", "op": "send", "inputs": {"hdr_nonce": "00"},
            "outputs": {"cell": "0a0b"}});
        assert_eq!(tr_decrypt(&send)?, vec![("cell", vec![0, 0x0a, 0x0b])]);
        let init = serde_json::json!({"id": "tr-0001", "op": "init", "inputs": {"sk": "01".repeat(32),
            "sb": "02".repeat(32), "spk_dh_sk": "03".repeat(32), "rpk_kem_seed": "04".repeat(64),
            "dh_s_sk": "05".repeat(32), "kem_s_seed": "06".repeat(64), "m": "07".repeat(32)}});
        assert!(tr_decrypt(&init)?.is_empty());
        let state = tr_state(&init)?;
        let [(label, bytes)] = state.as_slice() else {
            return Err(Error("tr_state: one seed expected".to_owned()));
        };
        // selector 0, then RatchetStateV1 of the responder's shape: 249 bytes
        assert_eq!(*label, "responder-state");
        assert_eq!(
            *bytes,
            cat(&[
                &[0, 1],
                &[2; 32],
                &[1; 32],
                &[3; 32],
                &[0],
                &[4; 64],
                &[0; 7],
                &[1],
                &[7; 32],
                &[1],
                &[5; 32],
                &[0; 14]
            ])
        );
        assert_eq!(bytes.len(), 250);
        assert!(tr_state(&send)?.is_empty());
        Ok(())
    }

    /// The `encodings` structures map to the selectors of the `proto_*` targets; `Signed/*` has no decoder; an
    /// unknown structure or CELLR context is refused.
    #[test]
    fn encodings_structures_map_to_selectors() -> Result<()> {
        assert_eq!(
            encodings_target("Record/HS2", None)?,
            Some(("proto_records", 3))
        );
        assert_eq!(
            encodings_target("Request/FETCH_MULTI", None)?,
            Some(("proto_frames", 0))
        );
        assert_eq!(
            encodings_target("Response/CELLR", Some("FETCH_MULTI"))?,
            Some(("proto_frames", 2))
        );
        assert_eq!(
            encodings_target("Response/OK", None)?,
            Some(("proto_frames", 1))
        );
        assert_eq!(
            encodings_target("ControlBody", None)?,
            Some(("proto_cell", 13))
        );
        assert_eq!(encodings_target("Signed/SEND", None)?, None);
        assert!(encodings_target("Response/CELLR", None).is_err());
        assert!(encodings_target("NewThing", None).is_err());
        let row = serde_json::json!({"id": "enc-9", "op": "decode", "expect": "reject",
            "inputs": {"structure": "HeaderV1", "bytes": "0102"}});
        assert_eq!(proto_cell(&row)?, vec![("negative", vec![1, 1, 2])]);
        assert!(proto_frames(&row)?.is_empty());
        assert!(unhex("0g").is_err() && unhex("0").is_err() && unhex("0A").is_err());
        Ok(())
    }
}
