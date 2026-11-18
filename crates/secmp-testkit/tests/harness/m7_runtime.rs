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
