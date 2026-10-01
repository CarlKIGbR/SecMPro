// SPDX-License-Identifier: AGPL-3.0-or-later
//! Performance of SecMP-TR (docs/07 M3 acceptance "encrypt+decrypt of a message < 3 ms"; M3 plan D11). Run by
//! `cargo xtask step perf` (ci-full) as `cargo run --release --locked -p secmp-proto --example tr-perf --
//! target/tr-perf.txt`; the gate reads the file and fails if a maximum reaches 3 ms (`expect::TR_PERF_MAX_MS`).
//!
//! One session (A initiator, B responder, randomness from the OS: `OsEntropy` through `encrypt`/`decrypt`), then
//! [`N`] messages of each kind, each timed from `encrypt` to the end of `commit` — `persist` and `commit` with a
//! closure that keeps the serialised state and does nothing else, so the serialisation (`RatchetStateV1`) is part
//! of the time:
//! - `chain`: A's next message on its established sending chain (the receiver advances its chain, no DH step);
//! - `step`: messages in alternating directions, each the first of a new chain, so that every receiver performs a
//!   DH step (`Decaps`, two X25519, ML-KEM-768 and X25519 key generation, `Encaps`).
//!
//! [`WARMUP`] messages of each kind run first and are not recorded. After each timed message (outside the timing)
//! the delivered content is checked, and the receiver's root key `rk` is compared with the one before (in constant
//! time): unchanged for `chain`, changed for `step` — the kinds are what they claim to be.
//!
//! Output (`key=value` lines): `host` (the target triple this example was built for, the host of a `cargo run`
//! without `--target`), `n`, `warmup`, and per kind `<kind>_median_us` and `<kind>_max_us` (microseconds, one
//! decimal). On failure the file holds `error=<reason>` and the exit status is a failure.
#![forbid(unsafe_code)]

use std::hint::black_box;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use secmp_crypto::{ConstantTimeEq, MlKem768Dk, SecretBytes, X25519Secret, Zeroizing};
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::RatchetState;
use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody, Content, ContentBody};

/// Timed messages per kind.
const N: usize = 200;
/// Messages per kind before the timed ones (not recorded).
const WARMUP: usize = 20;
/// `rk` in `RatchetStateV1` (`fmt u8 ‖ sb[32] ‖ rk[32] ‖ …`, `secmp_proto::tr` state encoding).
const RK_AT: std::ops::Range<usize> = 33..65;

/// Why the measurement failed (written as `error=…`).
type Failure = &'static str;

/// The target triple this example was compiled for.
fn host() -> String {
    let vendor = if cfg!(target_vendor = "apple") {
        "apple"
    } else if cfg!(target_vendor = "pc") {
        "pc"
    } else {
        "unknown"
    };
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    };
    let env = if cfg!(target_env = "gnu") {
        "-gnu"
    } else if cfg!(target_env = "msvc") {
        "-msvc"
    } else if cfg!(target_env = "musl") {
        "-musl"
    } else {
        ""
    };
    format!("{}-{vendor}-{os}{env}", std::env::consts::ARCH)
}

/// A text message with sequence number `seq`.
fn message(seq: u64) -> Content {
    Content {
        seq,
        ts: 0,
        body: ContentBody::Batch(BatchBody {
            messages: vec![AppMessage {
                msg_id: [7; 16],
                kind: AppKind::Text,
                expire_after: 0,
                payload: Zeroizing::new(b"tr-perf: a short text message".to_vec()),
            }],
        }),
    }
}

/// A fresh session: `SK`, `sb`, B's signed and ratchet prekeys from the OS.
fn session() -> Result<(RatchetState, RatchetState), Failure> {
    const SETUP: Failure = "session setup failed";
    let sk = SecretBytes::<32>::random().map_err(|_| SETUP)?;
    let sb = [0x5b; 32];
    let spk = X25519Secret::generate().map_err(|_| SETUP)?;
    let rpk = MlKem768Dk::generate().map_err(|_| SETUP)?;
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).map_err(|_| SETUP)?;
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).map_err(|_| SETUP)?;
    let a = RatchetState::init_initiator(&sk, &sb, &spk_pub, &rpk_ek).map_err(|_| SETUP)?;
    let b = RatchetState::init_responder(&sk, &sb, spk, rpk).map_err(|_| SETUP)?;
    Ok((a, b))
}

/// The receiver's `rk`, from its persistence encoding.
fn root_key(state: &RatchetState) -> Result<[u8; 32], Failure> {
    let bytes = state.to_bytes().map_err(|_| "state encoding failed")?;
    bytes
        .get(RK_AT)
        .and_then(|rk| <[u8; 32]>::try_from(rk).ok())
        .ok_or("state encoding too short")
}

/// One message `sender → receiver`, timed from `encrypt` to the end of `commit` (µs). Checks the delivered content
/// and whether the receiver's root key changed (`step`) or not.
fn one(
    sender: RatchetState,
    receiver: RatchetState,
    seq: u64,
    step: bool,
) -> Result<(RatchetState, RatchetState, f64), Failure> {
    let content = message(seq);
    let rk_before = root_key(&receiver)?;
    // the persistence of `persist`/`commit`: a no-op that keeps the serialised state from being optimised away
    let keep = |state: &[u8]| {
        black_box(state);
        Ok::<(), Failure>(())
    };
    let start = Instant::now();
    let (sender, cell) = sender
        .encrypt(&content)
        .map_err(|_| "encrypt refused")?
        .persist(keep)?;
    let (receiver, plaintext) = receiver
        .decrypt(cell.as_bytes())
        .map_err(|_| "decrypt refused")?
        .commit(keep)?;
    let micros = start.elapsed().as_secs_f64() * 1e6;
    let delivered = plaintext.content().map_err(|_| "content not decodable")?;
    if delivered.seq != seq {
        return Err("wrong content delivered");
    }
    let rk_after = root_key(&receiver)?;
    if bool::from(rk_before.ct_eq(&rk_after)) == step {
        return Err(if step {
            "a step message did not step the receiver"
        } else {
            "a chain message stepped the receiver"
        });
    }
    Ok((sender, receiver, micros))
}

/// Median and maximum of `times` (µs).
fn stats(mut times: Vec<f64>) -> Result<(f64, f64), Failure> {
    times.sort_by(f64::total_cmp);
    let median = times.get(times.len() / 2).copied();
    median.zip(times.last().copied()).ok_or("no measurement")
}

/// Both kinds, `WARMUP + N` messages each; the report lines.
fn measure() -> Result<Vec<String>, Failure> {
    let (mut a, mut b) = session()?;
    let mut seq = 0_u64;
    let mut next = || {
        seq = seq.wrapping_add(1);
        seq
    };
    // A → B (B steps), B → A (A steps), A → B (B steps): A's sending chain is now established on B's side
    (a, b, _) = one(a, b, next(), true)?;
    (b, a, _) = one(b, a, next(), true)?;
    (a, b, _) = one(a, b, next(), true)?;
    // chain: A → B on that chain
    let mut chain = Vec::with_capacity(N);
    for i in 0..WARMUP.saturating_add(N) {
        let micros;
        (a, b, micros) = one(a, b, next(), false)?;
        if i >= WARMUP {
            chain.push(micros);
        }
    }
    // step: alternating, B first (B has not sent on its chain since its last step), each message a new chain
    let mut step = Vec::with_capacity(N);
    for i in 0..WARMUP.saturating_add(N) {
        let micros;
        if i % 2 == 0 {
            (b, a, micros) = one(b, a, next(), true)?;
        } else {
            (a, b, micros) = one(a, b, next(), true)?;
        }
        if i >= WARMUP {
            step.push(micros);
        }
    }
    let (chain_median, chain_max) = stats(chain)?;
    let (step_median, step_max) = stats(step)?;
    Ok(vec![
        format!("host={}", host()),
        format!("n={N}"),
        format!("warmup={WARMUP}"),
        format!("chain_median_us={chain_median:.1}"),
        format!("chain_max_us={chain_max:.1}"),
        format!("step_median_us={step_median:.1}"),
        format!("step_max_us={step_max:.1}"),
    ])
}

fn main() -> ExitCode {
    let path = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tr-perf.txt"),
        PathBuf::from,
    );
    let (lines, status) = match measure() {
        Ok(lines) => (lines, ExitCode::SUCCESS),
        Err(reason) => (vec![format!("error={reason}")], ExitCode::FAILURE),
    };
    let mut text = lines.join("\n");
    text.push('\n');
    if std::fs::write(path, text).is_err() {
        return ExitCode::FAILURE;
    }
    status
}
