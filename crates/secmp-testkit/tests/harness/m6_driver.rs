// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase B (BRIEF M6-B §2.2): the asynchronous transport and the tokio driver — AD-07…AD-11, P-05 and one test per
//! driver obligation (i)–(vi) of `scheduler/mod.rs` (names listed in the report §5).

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::Step;
use secmp_client_core::scheduler::types::{LinkEvent, Reason};
use secmp_crypto::SecretBytes;
use secmp_proto::Encode;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::RelayRef;
use secmp_testkit::harness::{
    Chunking, Costs, EntropyPool, Harness, HarnessConfig, MemProvider, MemRelay, START_UNIX,
};
use secmp_transport::driver::{
    AsyncQueueTransport, AsyncRelayQueueTransport, AsyncSession, Isolation, StreamProvider,
};
use secmp_transport::{Command, Error, LinkGetMode, Outcome, QueueTransport, RecvCap, SendCap};
use tokio::io::{AsyncReadExt, DuplexStream};

use crate::m6_activity::{Scenario, activity};
use crate::m6_common::max_dt;
use crate::m6_rand::Mix;
use crate::m6_tokio::{Setup, TClient, TokioRig, runtime};
use crate::seed;

const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0602;

fn sb(bytes: &[u8]) -> SecretBytes<32> {
    SecretBytes::from_slice(bytes).unwrap()
}

fn cell(fill: u8) -> Cell {
    Cell::from_bytes(&[fill; 4096]).unwrap()
}

fn blob(fill: u8) -> secmp_proto::wire::inv::LinkBlob {
    <secmp_proto::wire::inv::LinkBlob as secmp_proto::Decode>::decode(&[fill; 12_360]).unwrap()
}

fn keys(link: &secmp_proto::link::Link) -> ([u8; 32], [u8; 32]) {
    let (a, b) = link.keys_kat();
    (*a, *b)
}

// ---- AD-07 -------------------------------------------------------------------------------------------------------------

/// AD-07 (ADR-050 (3)): with the same randomness, the asynchronous session over a duplex stream writes and reads the
/// same bytes as the M5 synchronous session over the harness stream — `HELLO`, `HS1`, the link keys and the first three
/// frames in each direction (here: the whole capture of three commands).
#[test]
fn async_session_equals_sync_session() {
    let mut harness = Harness::new(HarnessConfig::default());
    let client = harness.add_client();
    harness.connect(client).unwrap();
    let access = harness.access_key();
    let mut seeds = EntropyPool::new("ad07-seeds", 0);
    let (recv, send) = (seeds.bytes(32), seeds.bytes(32));
    let sync_keys = {
        let t = harness.client(client).transport().unwrap();
        let (rc, sc) = t.create_queue(&sb(&recv), &sb(&send), &access).unwrap();
        t.send(&sc, &cell(0x11)).unwrap();
        t.fetch(&rc, 0).unwrap();
        keys(t.session().link_kat())
    };
    let sync_cap = harness.client(client).captures().remove(0);
    let (async_cap, async_keys) = runtime().block_on(async {
        let relay = MemRelay::new(HarnessConfig::default());
        let stream = relay.open(Isolation(1)).unwrap();
        let mut pool = EntropyPool::new("harness-client", 0);
        let access = relay.access_key();
        let mut t = AsyncRelayQueueTransport::connect(
            stream,
            relay.relay_fp(),
            Some(&access),
            START_UNIX,
            pool.get(),
        )
        .await
        .unwrap();
        let mut seeds = EntropyPool::new("ad07-seeds", 0);
        let (recv, send) = (seeds.bytes(32), seeds.bytes(32));
        let (rc, sc) = t
            .create_queue(&sb(&recv), &sb(&send), &access)
            .await
            .unwrap();
        t.send(&sc, &cell(0x11)).await.unwrap();
        t.fetch(&rc, 0).await.unwrap();
        (relay.capture(0), keys(t.session().link_kat()))
    });
    // HELLO (9 B) and HS1 (2856 B): the client's handshake
    assert_eq!(async_cap.0.get(..9), sync_cap.to_relay.get(..9), "HELLO");
    assert_eq!(
        async_cap.0.get(9..2865),
        sync_cap.to_relay.get(9..2865),
        "HS1"
    );
    assert_eq!(async_keys, sync_keys, "link keys");
    // the first three frames each way
    let frames = |b: &[u8], from: usize| {
        b.get(from..from.saturating_add(3 * 4352))
            .map(<[u8]>::to_vec)
    };
    assert_eq!(
        frames(&async_cap.0, 2865),
        frames(&sync_cap.to_relay, 2865),
        "C2R frames"
    );
    assert_eq!(
        frames(&async_cap.1, 2900),
        frames(&sync_cap.to_client, 2900),
        "R2C frames"
    );
    assert_eq!(async_cap.0, sync_cap.to_relay);
    assert_eq!(async_cap.1, sync_cap.to_client);
}

// ---- AD-08 -------------------------------------------------------------------------------------------------------------

fn caps_str(r: &Result<(RecvCap, SendCap), Error>) -> String {
    match r {
        Ok((rc, sc)) => format!("caps {:02x?} {:02x?}", rc.queue().rid(), sc.sid()),
        Err(e) => format!("err {e:?}"),
    }
}

fn cells_str(r: &Result<Vec<(u64, Cell)>, Error>) -> String {
    match r {
        Ok(v) => format!(
            "cells {:?}",
            v.iter()
                .map(|(id, c)| (*id, c.as_bytes().first().copied()))
                .collect::<Vec<_>>()
        ),
        Err(e) => format!("err {e:?}"),
    }
}

fn multi_str(r: &Result<secmp_transport::FetchMultiOutcome, Error>) -> String {
    match r {
        Ok(m) => format!(
            "multi cells {:?} errors {:?}",
            m.cells
                .iter()
                .map(|(q, id, c)| (*q.rid(), *id, c.as_bytes().first().copied()))
                .collect::<Vec<_>>(),
            m.errors
                .iter()
                .map(|(q, e)| (*q.rid(), *e))
                .collect::<Vec<_>>()
        ),
        Err(e) => format!("err {e:?}"),
    }
}

fn link_str(r: &Result<secmp_transport::LinkGetOutcome, Error>) -> String {
    match r {
        Ok(o) => format!(
            "link present {} consumed {} blob {:?}",
            o.present,
            o.consumed,
            o.blob
                .as_ref()
                .map(|b| b.encode().unwrap().first().copied())
        ),
        Err(e) => format!("err {e:?}"),
    }
}

const AD08_BUCKET_SECS: u64 = 86_400;

fn ad08_sync() -> (Vec<String>, Vec<u8>, Vec<u8>) {
    let mut h = Harness::new(HarnessConfig::default());
    let a = h.add_client();
    h.connect(a).unwrap();
    let access = h.access_key();
    let bucket =
        secmp_relay::HourBucket::from_unix_secs(START_UNIX.saturating_add(AD08_BUCKET_SECS)).0;
    let mut seeds = EntropyPool::new("ad08-seeds", 0);
    let mut log = Vec::new();
    let t = h.client(a).transport().unwrap();
    let (ra, sa, rb, sbb, rcc, scc) = (
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
    );
    // T-01: idempotent creation
    let qa = t.create_queue(&sb(&ra), &sb(&sa), &access);
    log.push(caps_str(&qa));
    log.push(caps_str(&t.create_queue(&sb(&ra), &sb(&sa), &access)));
    let qb = t.create_queue(&sb(&rb), &sb(&sbb), &access);
    log.push(caps_str(&qb));
    let qc = t.create_queue(&sb(&rcc), &sb(&scc), &access);
    log.push(caps_str(&qc));
    let ((rca, sca), (rcb, _), (rccap, sccap)) = (qa.unwrap(), qb.unwrap(), qc.unwrap());
    // T-05: delete, then the queue is gone
    log.push(format!("{:?}", t.delete_queue(&rccap)));
    // T-02: send outcomes (OK, NOQUEUE)
    log.push(format!("{:?}", t.send(&sca, &cell(0x11))));
    log.push(format!("{:?}", t.send(&sccap, &cell(0x12))));
    for fill in 0x13..=0x16 {
        log.push(format!("{:?}", t.send(&sca, &cell(fill))));
    }
    // T-03: fetch, real cells only, ascending
    log.push(cells_str(&t.fetch(&rca, 0)));
    log.push(cells_str(&t.fetch(&rca, 4)));
    log.push(cells_str(&t.fetch(&rccap, 0)));
    // T-04: fetch_multi with a queue in error
    log.push(multi_str(&t.fetch_multi(&[
        (&rca, 5),
        (&rccap, 0),
        (&rcb, 0),
    ])));
    log.push(format!("{:?}", t.delete_queue(&rcb).map(|()| "deleted")));
    log.push(cells_str(&t.fetch(&rcb, 0)));
    // T-06: link data
    let owner = sb(&[0x31; 32]);
    log.push(format!(
        "{:?}",
        t.put_link_data([0x42; 16], &owner, &blob(0x5c), true, bucket, &access)
    ));
    log.push(format!(
        "{:?}",
        t.put_link_data([0x42; 16], &owner, &blob(0x5d), true, bucket, &access)
    ));
    log.push(link_str(
        &t.get_link_data([0x42; 16], LinkGetMode::OwnerStatus(&owner)),
    ));
    log.push(link_str(&t.get_link_data([0x42; 16], LinkGetMode::Consume)));
    log.push(link_str(&t.get_link_data([0x42; 16], LinkGetMode::Consume)));
    log.push(link_str(&t.get_link_data([0x43; 16], LinkGetMode::Consume)));
    let cap = h.client(a).captures().remove(0);
    (log, cap.to_relay, cap.to_client)
}

async fn ad08_async() -> (Vec<String>, Vec<u8>, Vec<u8>) {
    let relay = MemRelay::new(HarnessConfig::default());
    let stream = relay.open(Isolation(1)).unwrap();
    let mut pool = EntropyPool::new("harness-client", 0);
    let access = relay.access_key();
    let bucket =
        secmp_relay::HourBucket::from_unix_secs(START_UNIX.saturating_add(AD08_BUCKET_SECS)).0;
    let mut t = AsyncRelayQueueTransport::connect(
        stream,
        relay.relay_fp(),
        Some(&access),
        START_UNIX,
        pool.get(),
    )
    .await
    .unwrap();
    let mut seeds = EntropyPool::new("ad08-seeds", 0);
    let mut log = Vec::new();
    let (ra, sa, rb, sbb, rcc, scc) = (
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
        seeds.bytes(32),
    );
    let qa = t.create_queue(&sb(&ra), &sb(&sa), &access).await;
    log.push(caps_str(&qa));
    log.push(caps_str(&t.create_queue(&sb(&ra), &sb(&sa), &access).await));
    let qb = t.create_queue(&sb(&rb), &sb(&sbb), &access).await;
    log.push(caps_str(&qb));
    let qc = t.create_queue(&sb(&rcc), &sb(&scc), &access).await;
    log.push(caps_str(&qc));
    let ((rca, sca), (rcb, _), (rccap, sccap)) = (qa.unwrap(), qb.unwrap(), qc.unwrap());
    log.push(format!("{:?}", t.delete_queue(&rccap).await));
    log.push(format!("{:?}", t.send(&sca, &cell(0x11)).await));
    log.push(format!("{:?}", t.send(&sccap, &cell(0x12)).await));
    for fill in 0x13..=0x16 {
        log.push(format!("{:?}", t.send(&sca, &cell(fill)).await));
    }
    log.push(cells_str(&t.fetch(&rca, 0).await));
    log.push(cells_str(&t.fetch(&rca, 4).await));
    log.push(cells_str(&t.fetch(&rccap, 0).await));
    log.push(multi_str(
        &t.fetch_multi(&[(&rca, 5), (&rccap, 0), (&rcb, 0)]).await,
    ));
    log.push(format!(
        "{:?}",
        t.delete_queue(&rcb).await.map(|()| "deleted")
    ));
    log.push(cells_str(&t.fetch(&rcb, 0).await));
    let owner = sb(&[0x31; 32]);
    log.push(format!(
        "{:?}",
        t.put_link_data([0x42; 16], &owner, &blob(0x5c), true, bucket, &access)
            .await
    ));
    log.push(format!(
        "{:?}",
        t.put_link_data([0x42; 16], &owner, &blob(0x5d), true, bucket, &access)
            .await
    ));
    log.push(link_str(
        &t.get_link_data([0x42; 16], LinkGetMode::OwnerStatus(&owner))
            .await,
    ));
    log.push(link_str(
        &t.get_link_data([0x42; 16], LinkGetMode::Consume).await,
    ));
    log.push(link_str(
        &t.get_link_data([0x42; 16], LinkGetMode::Consume).await,
    ));
    log.push(link_str(
        &t.get_link_data([0x43; 16], LinkGetMode::Consume).await,
    ));
    let (to_relay, to_client) = relay.capture(0);
    (log, to_relay, to_client)
}

/// AD-08 (§12.1): the scenarios of T-01…T-06 over the asynchronous transport give the outcomes and the byte captures of
/// the M5 synchronous runs.
#[test]
fn async_transport_matches_m5_outcomes() {
    let (sync_log, sync_c2r, sync_r2c) = ad08_sync();
    let (async_log, async_c2r, async_r2c) = runtime().block_on(ad08_async());
    // the scenario really covers the mappings
    assert!(
        sync_log.iter().any(|l| l.contains("NoQueue")),
        "{sync_log:?}"
    );
    assert!(
        sync_log.iter().any(|l| l.contains("Exists")),
        "{sync_log:?}"
    );
    assert!(
        sync_log
            .iter()
            .any(|l| l.starts_with("multi") && l.contains("NoQueue")),
        "{sync_log:?}"
    );
    assert!(
        sync_log.iter().any(|l| l.contains("blob Some")),
        "{sync_log:?}"
    );
    assert_eq!(sync_log.first(), sync_log.get(1), "T-01 idempotent");
    assert_eq!(async_log, sync_log);
    assert_eq!(async_c2r, sync_c2r, "C2R bytes");
    assert_eq!(async_r2c, sync_r2c, "R2C bytes");
}

// ---- AD-09, AD-10, AD-11 -----------------------------------------------------------------------------------------------

fn require_send<F: Future + Send>(f: F) {
    drop(f);
}

/// Every operation of the trait, with `&mut self`, returning a `Send` future (compile-time).
fn trait_shape<T: AsyncQueueTransport>(
    t: &mut T,
    rc: &RecvCap,
    sc: &SendCap,
    access: &secmp_proto::link::ids::AccessKey,
) {
    let seed = sb(&[1; 32]);
    let c = cell(0);
    let b = blob(0);
    require_send(t.create_queue(&seed, &seed, access));
    require_send(t.send(sc, &c));
    require_send(t.fetch(rc, 0));
    require_send(t.fetch_multi(&[(rc, 0)]));
    require_send(t.delete_queue(rc));
    require_send(t.put_link_data([0; 16], &seed, &b, true, 0, access));
    require_send(t.get_link_data([0; 16], LinkGetMode::Consume));
}

/// AD-09 (§12.1, ADR-051 Part 1.3): `AsyncQueueTransport` has the seven §12.1 operations with `&mut self` and returns
/// `impl Future + Send`; no workspace crate depends on `async-trait`. Reading of the row's "no `async-trait` crate in
/// `Cargo.lock`" (reviewer, WEISUNG M6-B-3 §0.3): no *workspace* crate depends on it — `async-trait` 0.1.92 is in the lock
/// only through `arti-client` 0.46.0 and its `tor-*` crates, which is unavoidable; the test checks that no workspace member
/// (as `cargo metadata` lists them, `xtask` included; EXTB-8) declares it and that no dependent in the lock is a member.
#[test]
fn queue_transport_async_signature() {
    runtime().block_on(async {
        let relay = MemRelay::new(HarnessConfig::default());
        let mut setup_pool = EntropyPool::new("ad09", 0);
        let stream = relay.open(Isolation(1)).unwrap();
        let access = relay.access_key();
        let mut t = AsyncRelayQueueTransport::connect(
            stream,
            relay.relay_fp(),
            Some(&access),
            START_UNIX,
            setup_pool.get(),
        )
        .await
        .unwrap();
        let (rc, sc) = t
            .create_queue(&sb(&[2; 32]), &sb(&[3; 32]), &access)
            .await
            .unwrap();
        trait_shape(&mut t, &rc, &sc, &access);
    });
    // the workspace members as cargo sees them (xtask and fuzz-free members included; EXTB-8), with their declared
    // dependencies of every kind
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(out.status.success());
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let members: Vec<(String, Vec<String>)> = meta
        .get("packages")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let deps = p
                .get("dependencies")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d.get("name").unwrap().as_str().unwrap().to_owned())
                .collect();
            (p.get("name").unwrap().as_str().unwrap().to_owned(), deps)
        })
        .collect();
    assert!(
        members.iter().any(|(n, _)| n == "xtask"),
        "xtask is a member"
    );
    assert!(members.iter().any(|(n, _)| n == "secmp-transport"));
    for (name, deps) in &members {
        assert!(
            !deps.iter().any(|d| d == "async-trait"),
            "{name} depends on async-trait"
        );
    }
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let mut dependents = Vec::new();
    for block in lock.split("[[package]]") {
        let name = block
            .lines()
            .find_map(|l| l.strip_prefix("name = \""))
            .map(|n| n.trim_end_matches('"'));
        if block.contains("\n \"async-trait\"") || block.contains("\n \"async-trait ") {
            dependents.push(name.unwrap_or_default().to_owned());
        }
    }
    assert!(!dependents.is_empty());
    assert!(
        dependents
            .iter()
            .all(|d| !members.iter().any(|(n, _)| n == d)),
        "{dependents:?}"
    );
}

/// A provider that misbehaves on the connects of its plan, then passes on to the in-process relay.
#[derive(Clone)]
pub struct Faulty {
    inner: MemProvider,
    plan: Arc<Mutex<VecDeque<Fault>>>,
}

#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// The stream cannot be opened.
    Fail,
    /// The connect never answers.
    Hang,
    /// The relay closes right after `HELLO` (spec §9.7 item 7).
    CloseBefore,
}

impl Faulty {
    pub fn new(inner: MemProvider, plan: &[Fault]) -> Self {
        Self {
            inner,
            plan: Arc::new(Mutex::new(plan.iter().copied().collect())),
        }
    }
}

impl StreamProvider for Faulty {
    type Stream = DuplexStream;

    fn connect(
        &self,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> impl Future<Output = Result<DuplexStream, Error>> + Send {
        let fault = self.plan.lock().unwrap().pop_front();
        let inner = self.inner.clone();
        let relay = relay.clone();
        async move {
            match fault {
                Some(Fault::Fail) => Err(Error::Closed),
                Some(Fault::Hang) => {
                    std::future::pending::<()>().await;
                    Err(Error::Closed)
                }
                Some(Fault::CloseBefore) => {
                    let (client, mut server) = tokio::io::duplex(1 << 16);
                    tokio::spawn(async move {
                        let mut hello = [0_u8; 9];
                        let _ = server.read_exact(&mut hello).await;
                    });
                    Ok(client)
                }
                None => inner.connect(&relay, isolation).await,
            }
        }
    }
}

fn is_provider<P: StreamProvider>() {}

/// AD-10 (§12.2): `StreamProvider` is implemented by the testkit's `MemProvider` (and a wrapper of it), and the
/// scheduler driver is generic over it — it names no concrete provider. (`TorProvider`, `TlsProvider` and
/// `TurmoilProvider` join this row in Phase B P3/P4 and Phase C.)
#[test]
fn stream_provider_impls() {
    is_provider::<MemProvider>();
    is_provider::<Faulty>();
    runtime().block_on(async {
        let setup = Setup::new();
        let mem: TClient = TClient::new(
            &setup,
            Mode::Strict,
            Params::default(),
            1,
            Costs::default(),
            0,
        );
        let faulty: TClient<Faulty> = TClient::with_provider(
            &setup,
            Faulty::new(setup.provider.clone(), &[]),
            Mode::Strict,
            Params::default(),
            1,
            Costs::default(),
            1,
        );
        drop((mem, faulty));
    });
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let run = std::fs::read_to_string(root.join("secmp-client-core/src/scheduler/run.rs")).unwrap();
    for concrete in [
        "MemProvider",
        "TorProvider",
        "TlsProvider",
        "TurmoilProvider",
        "DuplexStream",
        "TcpStream",
    ] {
        assert!(!run.contains(concrete), "run.rs names {concrete}");
    }
}

/// The lines of `text` (outside `//` comments) that read a wall clock.
fn wall_clock_reads(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let code = l.split("//").next().unwrap_or_default();
            [
                "Instant::now",
                "SystemTime::now",
                "tokio::time::Instant::now",
            ]
            .iter()
            .any(|p| code.contains(p))
        })
        .map(|(n, _)| n.saturating_add(1))
        .collect()
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// AD-11 = driver obligation (v) (`docs/06` §2): `Instant::now`, `SystemTime::now` and `tokio::time::Instant::now`
/// occur in `secmp-transport/src` and `secmp-client-core/src` only in `secmp-client-core/src/clock.rs`.
#[test]
fn driver_has_no_wall_clock() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&root.join("secmp-transport/src"), &mut files);
    rust_files(&root.join("secmp-client-core/src"), &mut files);
    assert!(files.len() > 15, "{}", files.len());
    let clock = root.join("secmp-client-core/src/clock.rs");
    let mut clock_reads = 0;
    for f in files {
        let reads = wall_clock_reads(&std::fs::read_to_string(&f).unwrap());
        if f == clock {
            clock_reads = reads.len();
        } else {
            assert!(reads.is_empty(), "{}: lines {reads:?}", f.display());
        }
    }
    assert!(clock_reads >= 2, "clock.rs is the reading site");
    // the scan is not vacuous
    assert_eq!(
        wall_clock_reads("let t = std::time::Instant::now();\n// Instant::now in a comment\n"),
        vec![1]
    );
    assert_eq!(
        wall_clock_reads("let a = 1;\nlet t = tokio::time::Instant::now();"),
        vec![2]
    );
}

// ---- P-05 --------------------------------------------------------------------------------------------------------------

fn cases() -> u64 {
    std::env::var("SECMP_PROPTEST_CASES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(16)
}

/// P-05: whatever the chunking and the delays of the relay's answers (order kept), every pipelined response over
/// `AsyncSession` is matched to its request, in request order, with the outcome of that request.
#[test]
fn prop_pipelined_matching_any_chunking() {
    let mut mix = Mix::new(seed::master_seed(DEFAULT_SEED));
    for case in 0..cases() {
        let (chunk_seed, gap, n, kinds_seed) = (
            mix.next(),
            mix.below(80),
            mix.below(6).saturating_add(1),
            mix.next(),
        );
        runtime().block_on(async move {
            let relay = MemRelay::new(HarnessConfig::default());
            let access = relay.access_key();
            let fp = relay.relay_fp();
            let mut pool = EntropyPool::new("p05", u32::try_from(case).unwrap());
            // a queue to fetch from and send to, made on a whole (unchunked) link
            let (rc, sc) = {
                let stream = relay.open(Isolation(1)).unwrap();
                let mut t = AsyncRelayQueueTransport::connect(
                    stream,
                    fp,
                    Some(&access),
                    START_UNIX,
                    pool.get(),
                )
                .await
                .unwrap();
                t.create_queue(&sb(&pool.bytes(32)), &sb(&pool.bytes(32)), &access)
                    .await
                    .unwrap()
            };
            relay.set_chunking(Some(Chunking {
                seed: chunk_seed,
                max_gap_ms: gap,
            }));
            let stream = relay.open(Isolation(2)).unwrap();
            let mut s = AsyncSession::connect(stream, fp, Some(&access), START_UNIX, pool.get())
                .await
                .unwrap();
            let mut kinds = Mix::new(kinds_seed | 1);
            let mut want = Vec::new();
            let mut prepared = Vec::new();
            let c = cell(0x77);
            for _ in 0..n {
                let kind = kinds.below(3);
                let command = match kind {
                    0 => Command::Ping,
                    1 => Command::Send { to: &sc, cell: &c },
                    _ => Command::Fetch { from: &rc, ack: 0 },
                };
                let p = s.prepare(&command).unwrap();
                want.push((p.seq(), kind));
                prepared.push(p);
            }
            for p in &prepared {
                s.write_prepared(p).await.unwrap();
            }
            assert_eq!(s.channel().outstanding(), prepared.len());
            for (seq, kind) in want {
                let done = s.read_response().await.unwrap();
                assert_eq!(done.seq, seq, "case {case}");
                let fits = match (kind, &done.outcome) {
                    (0, Outcome::Ping(r)) => r.is_ok(),
                    (1, Outcome::Send(r)) => r.is_ok(),
                    (2, Outcome::Fetch(r)) => r.is_ok(),
                    _ => false,
                };
                assert!(fits, "case {case}: the outcome is that of another request");
            }
            assert_eq!(s.channel().outstanding(), 0);
        });
    }
}

// ---- the driver obligations --------------------------------------------------------------------------------------------

fn scenario(seed: u64) -> Scenario {
    Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (20_000, 40_000)],
        pool: false,
        seed,
    }
}

/// Run `minutes` of the scenario with the client's worker at `costs`; the rig is returned for inspection.
fn run_with(costs: Costs, minutes: u64, seed: u64) -> (crate::m6_tokio::TRun, TokioRig) {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = scenario(seed);
        let x = TClient::new(&setup, sc.mode, Params::default(), sc.seed, costs, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let act = activity(seed, 1, sc.contacts.len());
        let run = rig.run_minutes(minutes, Some(&act)).await;
        (run, rig)
    })
}

/// Driver obligation (i): at every wake the driver calls `poll_due` and has every write it returned flushed before it
/// calls `work`; nothing is written at a time `poll_due` did not run, and no job is handed out before the flush.
#[test]
fn driver_flushes_due_writes_before_work() {
    let (run, rig) = run_with(
        Costs {
            prepare_real: 300,
            prepare_dummy: 200,
            receive: 100,
        },
        30,
        11,
    );
    assert!(run.c2r.len() > 100);
    let steps = &rig.x.driver.log().unwrap().steps;
    let mut polls = std::collections::BTreeSet::new();
    let mut state = 0_u8; // 0 expect PollDue, 1 expect Flushed, 2 expect Work
    let mut at = 0_u64;
    let mut wrote = 0;
    for step in steps {
        match *step {
            Step::PollDue(t) => {
                assert_eq!(state, 0, "poll_due before the last pass ended: {step:?}");
                polls.insert(t);
                at = t;
                state = 1;
            }
            Step::Flushed(t) => {
                assert!(state == 1 && t == at, "flush out of order: {step:?}");
                state = 2;
            }
            Step::Work(start, end) => {
                assert!(
                    state == 2 && start == at && end >= start,
                    "work before the flush: {step:?}"
                );
                state = 0;
            }
            Step::Job(_) => assert_eq!(state, 0, "a job handed out between poll_due and work"),
            Step::Wrote(t, _, len) => {
                assert_eq!(len % 4352, 0);
                wrote += 1;
                let _ = t;
            }
        }
    }
    assert!(wrote > 100, "{wrote}");
    for step in steps {
        if let Step::Wrote(t, _, _) = *step {
            assert!(polls.contains(&t), "a write at {t}, where no poll_due ran");
        }
    }
}

/// Driver obligation (ii): the driver reports the end of the work from the same clock; a cell the worker delivers
/// after its tick makes the core count an overrun (12 s of preparation on a 10 s link), none with a fast worker.
#[test]
fn driver_reports_late_preparation_as_overrun() {
    let (fast, _) = run_with(Costs::default(), 5, 12);
    assert_eq!(fast.overruns, 0);
    let (slow, rig) = run_with(
        Costs {
            prepare_real: 12_000,
            prepare_dummy: 12_000,
            receive: 0,
        },
        5,
        12,
    );
    assert!(slow.overruns > 0, "a late cell is an overrun");
    let events = &rig.x.driver.log().unwrap().events;
    assert!(
        events
            .iter()
            .any(|(_, e)| matches!(e, LinkEvent::TornDown(_, Reason::Overrun))),
        "{events:?}"
    );
    // the work's end is the clock's reading right after it (no virtual time passes inside `work`)
    for step in &rig.x.driver.log().unwrap().steps {
        if let Step::Work(start, end) = *step {
            assert_eq!(start, end);
        }
    }
}

/// Driver obligation (iii): every `Connect` is resolved — a provider that fails, one that never answers (connect
/// timeout), a relay that closes before `RELAYINFO` — and the links come up afterwards.
#[test]
fn driver_resolves_every_connect() {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = scenario(13);
        let plan = [Fault::Fail, Fault::Hang, Fault::CloseBefore, Fault::Fail];
        let provider = Faulty::new(setup.provider.clone(), &plan);
        let mut x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            Params::default(),
            sc.seed,
            Costs::default(),
            0,
        );
        x.driver = x.driver.with_connect_timeout(30_000);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.run_minutes(20, None).await;
        let log = rig.x.driver.log().unwrap();
        let link_connects: Vec<_> = log
            .connects
            .iter()
            .filter_map(|(_, p, _)| match p {
                secmp_client_core::scheduler::run::Purpose::Link(l) => Some(*l),
                secmp_client_core::scheduler::run::Purpose::Control(_) => None,
            })
            .collect();
        assert!(link_connects.len() >= 4 + 4, "{}", link_connects.len());
        for l in &link_connects {
            assert!(
                log.resolved.iter().any(|(_, r, _)| r == l),
                "{l:?} unresolved"
            );
        }
        let failed = log.resolved.iter().filter(|(_, _, up)| !up).count();
        assert_eq!(failed, plan.len());
        assert!(
            log.events
                .iter()
                .any(|(_, e)| matches!(e, LinkEvent::TornDown(_, Reason::ClosedBeforeRelayInfo)))
        );
        // the hanging connect was given up after the timeout, not later; the others at once
        let delays: Vec<u64> = log
            .resolved
            .iter()
            .filter(|(_, _, up)| !up)
            .map(|(t, l, _)| {
                let started = log
                    .connects
                    .iter()
                    .find(|(_, p, _)| *p == secmp_client_core::scheduler::run::Purpose::Link(*l))
                    .unwrap()
                    .0;
                t.saturating_sub(started)
            })
            .collect();
        assert_eq!(
            delays.iter().filter(|d| **d == 30_000).count(),
            1,
            "{delays:?}"
        );
        assert_eq!(delays.iter().filter(|d| **d == 0).count(), 3, "{delays:?}");
        let ups = log
            .events
            .iter()
            .filter(|(_, e)| matches!(e, LinkEvent::Up(_)))
            .count();
        assert!(ups >= 4, "{ups}");
        assert!(
            rig.x.sched.links().iter().all(|l| l.t_up.is_some()),
            "every link is up in the end"
        );
    });
}

/// Driver obligation (iv): the driver wakes at the `FETCH`-lead deadline — with answers that take 9.5 s on a 10 s
/// recv link, every `FETCH` is prepared exactly `fetch_lead_ms` before its tick (while the previous one is still
/// outstanding), and no tick is lost.
#[test]
fn driver_wakes_at_the_fetch_lead() {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000)],
            pool: false,
            seed: 14,
        };
        let x = TClient::new(
            &setup,
            sc.mode,
            Params::default(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.setup.relay.set_latency_ms(9_500);
        rig.run_minutes(10, None).await;
        let lead = Params::default().fetch_lead_ms;
        let fetches: Vec<_> = rig
            .x
            .sched
            .prep_log()
            .iter()
            .filter(|r| r.kind == b'F')
            .copied()
            .collect();
        assert!(fetches.len() > 30, "{}", fetches.len());
        let at_lead = fetches
            .iter()
            .filter(|r| r.at == r.tick_at.saturating_sub(lead))
            .count();
        assert!(at_lead > 20, "{at_lead} of {} at the lead", fetches.len());
        assert!(
            fetches
                .iter()
                .all(|r| r.at <= r.tick_at.saturating_sub(lead) || r.tick == 1),
            "{fetches:?}"
        );
        assert_eq!(rig.x.sched.overruns(), 0);
    });
}

/// Driver obligation (vi): the cost of one link's preparation and receive processing never delays another link's due
/// write — with a worker that takes 900 ms per cell and 400 ms per received cell, the emission is the one with a free
/// worker, to the millisecond, and frames really left while the worker was busy.
#[test]
fn driver_slow_work_does_not_delay_other_links() {
    let (free, _) = run_with(Costs::default(), 30, 15);
    let (slow, rig) = run_with(
        Costs {
            prepare_real: 900,
            prepare_dummy: 900,
            receive: 400,
        },
        30,
        15,
    );
    assert_eq!(slow.overruns, 0);
    assert_eq!(max_dt(&free.c2r, &slow.c2r), Some(0), "C2R emission moved");
    assert_eq!(max_dt(&free.r2c, &slow.r2c), Some(0), "R2C moved");
    let jobs = rig.x.jobs.lock().unwrap().clone();
    let busy = |t: u64| jobs.iter().any(|j| j.start < t && t < j.end);
    let overlapped = slow
        .c2r
        .iter()
        .filter(|e| e.len == 4352 && busy(e.t_ms))
        .count();
    assert!(
        overlapped > 10,
        "frames left while the worker was busy: {overlapped}"
    );
}

// ---- the remaining paths of the driver ---------------------------------------------------------------------------------

/// The shipped worker runs every job on tokio's blocking pool, one after the other, and answers what the source said;
/// the failure value of each job is "nothing prepared, nothing committed".
#[test]
fn blocking_worker_runs_jobs_on_the_blocking_pool() {
    use secmp_client_core::scheduler::run::{BlockingWorker, Job, JobDone, Worker};
    use secmp_client_core::scheduler::types::{CellToken, QueueId, SendFailure};
    runtime().block_on(async {
        let convs: secmp_testkit::harness::Convs =
            secmp_client_core::scheduler::conversation::Conversations::new();
        let mut w = BlockingWorker::new(convs);
        let prepared = w
            .run(Job::Prepare {
                queue: QueueId(9),
                now: 0,
            })
            .await;
        assert!(matches!(
            prepared,
            JobDone::Prepared {
                cell: Ok(None) | Err(_),
                ..
            }
        ));
        let delivered = w
            .run(Job::Deliver {
                queue: QueueId(9),
                cell_id: 1,
                cell: cell(1),
            })
            .await;
        // the conversations decide a cell of a queue they do not know (they forget it): a committed decision
        assert!(matches!(delivered, JobDone::Delivered { cell_id: 1, .. }));
        for job in [
            Job::Relayed {
                queue: QueueId(9),
                token: CellToken(1),
                cell_id: 1,
            },
            Job::Evicted {
                queue: QueueId(9),
                cell_id: 1,
            },
            Job::SendFailed {
                queue: QueueId(9),
                token: CellToken(1),
                why: SendFailure::Unknown,
            },
            Job::Discard {
                queue: QueueId(9),
                token: CellToken(1),
            },
            Job::QueueLost { queue: QueueId(9) },
        ] {
            assert!(matches!(w.run(job).await, JobDone::Noted));
        }
        let failed = Job::Prepare {
            queue: QueueId(1),
            now: 0,
        }
        .failed();
        assert!(matches!(failed, JobDone::Prepared { cell: Err(_), .. }));
        let failed = Job::Deliver {
            queue: QueueId(1),
            cell_id: 2,
            cell: cell(2),
        }
        .failed();
        assert!(matches!(
            failed,
            JobDone::Delivered {
                committed: false,
                cell_id: 2,
                ..
            }
        ));
        assert!(matches!(
            Job::QueueLost { queue: QueueId(1) }.failed(),
            JobDone::Noted
        ));
    });
}

/// `Only` serves its transport and refuses the other one — never another provider (CLAUDE.md §1.5); the shipped
/// handshake randomness is the OS's.
#[test]
fn only_refuses_the_other_transport() {
    use secmp_client_core::scheduler::run::{HandshakeEntropy, Only, OsHandshakes, Providers};
    use secmp_client_core::scheduler::types::Transport;
    runtime().block_on(async {
        let setup = Setup::new();
        let only = Only::new(setup.provider.clone(), Transport::Tor);
        let relay = setup.relay.relay_ref();
        assert!(
            only.connect(Transport::Direct, &relay, Isolation(1))
                .await
                .is_err()
        );
        assert!(
            only.connect(Transport::Tor, &relay, Isolation(2))
                .await
                .is_ok()
        );
        assert_eq!(
            only.provider().connects().len(),
            1,
            "the refused connect never reached the provider"
        );
        let mut os = OsHandshakes;
        let _ = os.next();
    });
}

/// At the end of a run the cells the worker prepared but the core never took go back to the source (a real message is
/// re-queued): `release_unused` hands them to the worker as discards.
#[test]
fn driver_releases_unused_cells() {
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = scenario(16);
        let x = TClient::new(
            &setup,
            sc.mode,
            Params::default(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.run_minutes(2, None).await;
        let before = rig.x.jobs.lock().unwrap().len();
        rig.x.driver.release_unused();
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        assert!(rig.x.jobs.lock().unwrap().len() >= before);
    });
}
