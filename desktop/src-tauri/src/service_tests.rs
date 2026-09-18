//! Integration checks use disposable synthetic vaults and a local fake HTTP service only.
use crate::service::Shared;
use pman_core::{ipc::IpcRequest, HttpRequest, SiteInput};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

const PASSWORD: &str = "synthetic-test-password";
const PROOF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn request() -> HttpRequest {
    HttpRequest {
        site: "fixture".into(),
        method: "GET".into(),
        path: "/query".into(),
        capability: None,
        query: None,
        json_body: None,
        form: None,
    }
}
fn fixture(origin: &str) -> (tempfile::TempDir, Shared) {
    let dir = tempfile::tempdir().unwrap();
    let shared = Shared::open_at(dir.path().to_path_buf()).unwrap();
    {
        let mut core = shared.core.lock().unwrap();
        core.vault.create(PASSWORD).unwrap();
        core.vault
            .add_site(SiteInput::new(
                "fixture",
                origin,
                "api_token",
                json!({"token":"SYNTHETIC_PMAN_NEVER_OUTPUT_92745"}),
            ))
            .unwrap();
        core.vault
            .update_details("fixture", json!({"ai_enabled":true}))
            .unwrap();
        core.vault.ensure_harness("test-client").unwrap();
        core.vault.set_policy("test-client",json!({"allow":[{"site":"fixture","methods":["GET"],"paths":["/query"],"require_approval":false}]})).unwrap();
        core.vault
            .pair_client_for(
                "Fixture",
                "generic",
                "test-client",
                "test-pair",
                &hex::encode(Sha256::digest(PROOF.as_bytes())),
            )
            .unwrap();
    }
    shared.resume_password(PASSWORD).unwrap();
    (dir, shared)
}
fn status(shared: &Shared) -> Value {
    shared.dispatch(IpcRequest {
        client_id: "test-pair".into(),
        proof: PROOF.into(),
        operation: "status".into(),
        args: json!({}),
    })
}

#[test]
fn locked_management_keeps_real_authorized_requests_running() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        // Vault key derivation can take longer on loaded Windows builders; the
        // fixture must remain available until the first authorized request.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut accepted = 0;
        while accepted < 3 && Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            // Accepted sockets inherit nonblocking mode on Windows.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0u8; 8192];
            let size = stream.read(&mut bytes).unwrap();
            let text = String::from_utf8_lossy(&bytes[..size]);
            assert!(text.contains("SYNTHETIC_PMAN_NEVER_OUTPUT_92745"));
            let body = r#"{"ready":true}"#;
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            stream.write_all(response.as_bytes()).unwrap();
            accepted += 1;
        }
        accepted
    });
    let (_dir, shared) = fixture(&origin);
    let first = shared.http(request(), "test-client", None);
    assert!(first.envelope.ok, "first request failed: {first:?}");
    shared.lock_interface();
    assert!(shared.require_management().is_err());
    assert!(shared.http(request(), "test-client", None).envelope.ok);
    {
        let mut management = shared.management.lock().unwrap();
        management.authenticate();
        assert!(management.idle_lock(901));
    }
    assert!(shared.http(request(), "test-client", None).envelope.ok);
    assert_eq!(server.join().unwrap(), 3);
    assert_eq!(status(&shared)["service_running"], true);
}

#[test]
fn automatic_resume_and_persistent_pause_are_independent_from_management() {
    let (dir, shared) = fixture("https://example.test");
    shared.lock_interface();
    drop(shared);
    let shared = Shared::open_at(dir.path().to_path_buf()).unwrap();
    assert_eq!(shared.status().unwrap()["management_locked"], true);
    assert_eq!(status(&shared)["service_running"], true);
    shared.pause().unwrap();
    assert!(shared.require_management().is_err());
    drop(shared);
    let shared = Shared::open_at(dir.path().to_path_buf()).unwrap();
    assert_eq!(status(&shared)["service_running"], false);
    // A successful management-only Hello-equivalent unwrap does not resume AI.
    shared.unlock_protected(false, Some(0)).unwrap();
    assert!(shared.require_management().is_ok());
    assert_eq!(status(&shared)["service_running"], false);
    assert_eq!(status(&shared)["service_paused"], true);
    assert_eq!(
        shared
            .http(request(), "test-client", None)
            .envelope
            .error_code,
        "vault_locked"
    );
    shared.resume_password(PASSWORD).unwrap();
    assert_eq!(status(&shared)["service_running"], true);
}

#[test]
fn stale_management_verification_and_revoked_identity_are_rejected() {
    let (_dir, shared) = fixture("https://example.test");
    let epoch = shared.management.lock().unwrap().auth_epoch;
    shared.lock_interface();
    assert!(shared.unlock_protected(false, Some(epoch)).is_err());
    assert_eq!(
        shared
            .http(request(), "test-client", Some("https://other.test"))
            .envelope
            .error_code,
        "origin_mismatch"
    );
    shared
        .core
        .lock()
        .unwrap()
        .vault
        .revoke_client("test-pair")
        .unwrap();
    assert_eq!(status(&shared)["error_code"], "harness_invalid");
}

#[test]
fn management_lock_neither_changes_connection_evidence_nor_stops_api() {
    use pman_core::status::{CheckEvidence, DIMENSION_IDENTITY};
    let (_dir, shared) = fixture("https://example.test");
    {
        let mut core = shared.core.lock().unwrap();
        core.vault
            .record_check_evidence(
                "fixture",
                DIMENSION_IDENTITY,
                CheckEvidence {
                    state: "verified".into(),
                    checked_at: "2026-09-19T10:00:00".into(),
                    ..CheckEvidence::default()
                },
            )
            .unwrap();
    }
    let before = shared
        .core
        .lock()
        .unwrap()
        .vault
        .connection_status("fixture")
        .unwrap();
    assert_eq!(before.identity.state, "verified");
    assert_eq!(before.api.state, "unchecked");

    // Locking the management UI is a separate dimension from API capability.
    shared.lock_interface();
    assert!(shared.require_management().is_err());
    let after = shared
        .core
        .lock()
        .unwrap()
        .vault
        .connection_status("fixture")
        .unwrap();
    assert_eq!(before, after, "管理锁定不得改写连接状态证据");
    // The API dimension stays available and real calls keep working.
    assert_eq!(after.api.state, "unchecked");
    assert_eq!(status(&shared)["service_running"], true);
}
