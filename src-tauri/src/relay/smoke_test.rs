//! Real cross-process verification of the plaintext relay bridge (Step
//! 4's second verification layer, alongside `dispatch::tests`): spins up
//! `conn::run_once` against an actually-running relay binary and drives
//! it with the relay repo's `fakeclient` tool, exactly the way `web` (or,
//! for now, a human at a terminal) would exercise a paired amallo.
//!
//! Gated behind `AMALLO_SMOKE_RELAY_EXE` / `AMALLO_SMOKE_FAKECLIENT_EXE`
//! env vars pointing at pre-built binaries — unset, these tests are
//! skipped rather than failed, since they need real external processes
//! this crate has no business building itself. Run with:
//!
//! ```text
//! AMALLO_SMOKE_RELAY_EXE=/path/to/relay.exe \
//! AMALLO_SMOKE_FAKECLIENT_EXE=/path/to/fakeclient.exe \
//! cargo test --lib relay::smoke_test -- --test-threads=1 --nocapture
//! ```
//!
//! `--test-threads=1` matters: each test binds its own relay + amallo
//! ports, but running many at once is needless load for what's meant to
//! be a small, deliberate smoke check.

#![cfg(test)]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use base64::Engine;

use crate::relay::conn;

struct EnvGuard {
    relay_exe: String,
    fakeclient_exe: String,
}

fn require_env() -> Option<EnvGuard> {
    let relay_exe = std::env::var("AMALLO_SMOKE_RELAY_EXE").ok()?;
    let fakeclient_exe = std::env::var("AMALLO_SMOKE_FAKECLIENT_EXE").ok()?;
    Some(EnvGuard { relay_exe, fakeclient_exe })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {port} never opened");
}

/// A router standing in for the real Ollama-backed one, so this test
/// doesn't depend on Ollama actually running on the machine — it only
/// needs to prove the relay -> amallo -> router -> relay round trip
/// works, which is exactly what dispatch.rs's own in-process tests also
/// check, just now over a real WebSocket to a real relay binary instead
/// of direct function calls.
fn smoke_router() -> Router {
    Router::new()
        .route("/api/tags", get(|| async { "{\"models\":[]}" }))
        .route(
            "/api/chat",
            post(|| async {
                use axum::body::Body;
                use futures_util::stream;
                let lines: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
                    Ok(axum::body::Bytes::from_static(b"{\"message\":{\"content\":\"Hel\"}}\n")),
                    Ok(axum::body::Bytes::from_static(b"{\"message\":{\"content\":\"lo!\"}}\n")),
                    Ok(axum::body::Bytes::from_static(b"{\"done\":true}\n")),
                ];
                Body::from_stream(stream::iter(lines))
            }),
        )
}

#[tokio::test]
async fn plaintext_relay_round_trip_via_real_processes() {
    let Some(env) = require_env() else {
        eprintln!("skipping: set AMALLO_SMOKE_RELAY_EXE and AMALLO_SMOKE_FAKECLIENT_EXE to run this test");
        return;
    };

    let relay_port = free_port();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    let _relay = ChildGuard(
        Command::new(&env.relay_exe)
            .env("RELAY_ADDR", format!(":{relay_port}"))
            .env("RELAY_METRICS_ADDR", format!(":{}", free_port()))
            .env("RELAY_ALLOWED_ORIGINS", "*")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start relay binary"),
    );
    wait_for_port(relay_port).await;

    let relay_url = format!("ws://{relay_addr}");
    let mut pair_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut pair_id);
    let pair_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair_id);

    let router = smoke_router();
    let bearer = "smoke-test-bearer".to_string();

    let relay_url_clone = relay_url.clone();
    let conn_task = tokio::spawn(async move {
        // A single connection attempt is enough for this smoke test — no
        // supervisor/backoff loop needed.
        let _ = conn::run_once_insecure(&relay_url_clone, pair_id, router, bearer).await;
    });

    // Give amallo's side time to register as the agent before fakeclient
    // attaches — otherwise fakeclient would correctly (per spec) see
    // agent_offline.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let output = Command::new(&env.fakeclient_exe)
        .args([
            "-relay", &relay_url,
            "-pair", &pair_b64,
            "-insecure",
            "-method", "GET",
            "-path", "/api/tags",
            "-timeout", "10s",
        ])
        .output()
        .expect("run fakeclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("fakeclient stdout: {stdout}");
    eprintln!("fakeclient stderr: {stderr}");
    assert!(
        stdout.contains("\"models\":[]"),
        "expected the amallo-served /api/tags body in fakeclient's stdout, got: {stdout}"
    );

    // Streaming: POST /api/chat should arrive as multiple chunks, not
    // buffered into one — the real point of the whole streaming design.
    let output = Command::new(&env.fakeclient_exe)
        .args([
            "-relay", &relay_url,
            "-pair", &pair_b64,
            "-insecure",
            "-method", "POST",
            "-path", "/api/chat",
            "-timeout", "10s",
        ])
        .output()
        .expect("run fakeclient (chat)");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hel"), "missing first chunk: {stdout}");
    assert!(stdout.contains("lo!"), "missing second chunk: {stdout}");
    assert!(stdout.contains("done"), "missing final line: {stdout}");

    conn_task.abort();
}

/// Confirms the method/path allowlist (policy.rs) is actually enforced on
/// the real wire path, not just in dispatch.rs's in-process tests —
/// fakeclient requests `/api/create`, which must come back as a
/// `forbidden` ERROR frame rather than ever reaching smoke_router (which
/// doesn't even define that route, so a policy bypass would surface as a
/// generic 404 instead of the expected error code).
#[tokio::test]
async fn disallowed_path_is_rejected_over_the_real_wire() {
    let Some(env) = require_env() else {
        eprintln!("skipping: set AMALLO_SMOKE_RELAY_EXE and AMALLO_SMOKE_FAKECLIENT_EXE to run this test");
        return;
    };

    let relay_port = free_port();
    let _relay = ChildGuard(
        Command::new(&env.relay_exe)
            .env("RELAY_ADDR", format!(":{relay_port}"))
            .env("RELAY_METRICS_ADDR", format!(":{}", free_port()))
            .env("RELAY_ALLOWED_ORIGINS", "*")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start relay binary"),
    );
    wait_for_port(relay_port).await;

    let relay_url = format!("ws://127.0.0.1:{relay_port}");
    let mut pair_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut pair_id);
    let pair_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair_id);

    let relay_url_clone = relay_url.clone();
    let conn_task = tokio::spawn(async move {
        let _ = conn::run_once_insecure(&relay_url_clone, pair_id, smoke_router(), "bearer".into()).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut child = Command::new(&env.fakeclient_exe)
        .args([
            "-relay", &relay_url,
            "-pair", &pair_b64,
            "-insecure",
            "-method", "POST",
            "-path", "/api/create",
            "-timeout", "10s",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run fakeclient");

    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    child.wait().unwrap();

    assert!(
        stderr.contains("forbidden") || stderr.contains("ERROR"),
        "expected a forbidden/ERROR response for a disallowed path, got stderr: {stderr}"
    );

    conn_task.abort();
}
