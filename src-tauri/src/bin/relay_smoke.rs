//! Throwaway manual verification for Step 5's real encrypted relay path:
//! connects as the agent to a real relay (default: the deployed
//! wss://amallo-relay.tehfonsi.com) using amallo_lib::relay::conn's real
//! crypto handshake, with no Tauri app involved at all — the point of
//! the `run_once_with_status` split. Prints the pairing material so a
//! peer (e.g. the relay repo's `fakeclient`, or `web`) can attach and
//! exercise the full E2E path.
//!
//! Not wired into any build/test target — run directly:
//!   cargo run --bin relay_smoke [relay_url]

use amallo_lib::relay::conn;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use rand::RngCore;

#[tokio::main]
async fn main() {
    // Mirrors lib.rs's run() — rustls can't auto-select a crypto provider
    // on its own, so install one explicitly before anything touches TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let relay_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://amallo-relay.tehfonsi.com".to_string());

    let mut pair_id = [0u8; 16];
    let mut psk = [0u8; 32];
    rand::rng().fill_bytes(&mut pair_id);
    rand::rng().fill_bytes(&mut psk);

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    eprintln!("relay_smoke: relay={relay_url}");
    eprintln!("relay_smoke: pair_id={}", b64.encode(pair_id));
    eprintln!("relay_smoke: psk={}", b64.encode(psk));

    let router = Router::new().route(
        "/api/tags",
        get(|| async { r#"{"models":[{"name":"relay-smoke-test"}]}"# }),
    );

    let result = conn::run_once_with_status(
        &relay_url,
        pair_id,
        psk,
        router,
        "smoke-bearer".to_string(),
        |status| eprintln!("relay_smoke: status -> {status:?}"),
    )
    .await;

    match result {
        Ok(()) => eprintln!("relay_smoke: session ended cleanly"),
        Err(e) => eprintln!("relay_smoke: session ended with error: {e}"),
    }
}
