// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-C1b: the host runtime (`secmp_client_core::api::runtime`) as a library, with a real relay behind its direct TLS listener.

use secmp_client_core::api::runtime::{
    Answer, Call, RuntimeConfig, create_profile, read_relay_ref, start,
};
use secmp_client_core::api::{Error, Request};
use secmp_crypto::Zeroizing;
use secmp_testkit::harness::e2e::E2eRelay;

/// C1-1 (CLAUDE.md §1.4): `Call::Core(Request::Export)` is refused with `Error::Unsupported` — it would run Argon2id and write
/// a file under the store's lock on the loop that keeps the schedule — and the file does not exist afterwards, so
/// `Core::handle` was never reached (that the loop's ticks stay on time is not observable here). A request that is admitted
/// is answered all the same.
#[test]
fn export_through_call_core_is_refused() {
    let root = std::env::temp_dir().join(format!("secmp-m7-runtime-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let relay = E2eRelay::start(&root.join("relay"));
    let relay_text = std::fs::read_to_string(relay.ref_path()).unwrap();
    assert!(read_relay_ref(&relay_text).is_ok());
    let dir = root.join("profile");
    create_profile(&dir, b"correct horse", Some(&relay_text)).unwrap();
    let target = root.join("backup.smpb");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let cfg = RuntimeConfig {
            direct: true,
            name: "m7-runtime".to_owned(),
        };
        let (client, serve) = start(&dir, b"correct horse", cfg).unwrap();
        let serving = tokio::task::spawn_local(serve.run());
        let export = Request::Export {
            path: target.clone(),
            passphrase: Zeroizing::new(b"backup horse".to_vec()),
            confirm: true,
            force: true,
        };
        let refused = client.call(Call::Core(export)).await;
        assert_eq!(refused.err(), Some(Error::Unsupported));
        assert!(!target.exists(), "the request never reached the core");
        let contacts = client.call(Call::Core(Request::Contacts)).await;
        assert!(matches!(contacts, Ok(Answer::Core(_))));
        let closed = client.call(Call::Quit).await;
        assert!(matches!(closed, Ok(Answer::Closed)));
        serving.await.unwrap();
    });
}

/// B0 (CLAUDE.md §1.4; M7-C2): a call that takes seconds (the `kat` hook holds the next `Core::handle` for 3 s) runs as a hub
/// job on the blocking pool: the loop keeps running chunks meanwhile (the `kat` chunk counter advances at least twice), and
/// the call is answered after the hold.
#[test]
fn loop_keeps_running_during_a_slow_call() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use secmp_client_core::api::runtime::hooks;

    let root = std::env::temp_dir().join(format!("secmp-m7-slow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("profile");
    std::fs::create_dir_all(&dir).unwrap();
    create_profile(&dir, b"correct horse", None).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let cfg = RuntimeConfig {
            direct: true,
            name: "m7-slow".to_owned(),
        };
        let (client, serve) = start(&dir, b"correct horse", cfg).unwrap();
        let serving = tokio::task::spawn_local(serve.run());
        let before = hooks::CHUNKS.load(Ordering::SeqCst);
        hooks::HOLD_HANDLE_MS.store(3_000, Ordering::SeqCst);
        let started = Instant::now();
        let answer = client.call(Call::Core(Request::Contacts)).await;
        let took = started.elapsed();
        assert!(matches!(answer, Ok(Answer::Core(_))));
        assert!(took >= Duration::from_secs(3), "{took:?}");
        let chunks = hooks::CHUNKS.load(Ordering::SeqCst).saturating_sub(before);
        assert!(chunks >= 2, "{chunks} chunks ran during the call");
        let closed = client.call(Call::Quit).await;
        assert!(matches!(closed, Ok(Answer::Closed)));
        serving.await.unwrap();
    });
}
