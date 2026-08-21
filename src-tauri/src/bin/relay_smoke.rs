//! Throwaway manual verification for Step 5's real encrypted relay path:
//! connects as the agent to a real relay (default: the deployed
//! wss://relay.41tunnels.com) using amallo_lib::relay::conn's real
//! crypto handshake, with no Tauri app involved at all — the point of
//! the `run_once_with_status` split. Prints the pairing material so a
//! peer (e.g. the relay repo's `fakeclient`, or `web`) can attach and
//! exercise the full E2E path.
//!
//! Passing an API key as the second argument opens the connection in
//! dual mode, so both lanes ride the one socket: the E2E pairing as
//! before, plus the OpenAI-compatible endpoint reachable at
//! `http(s)://<relay-host>/<api_key>/v1/...`. The literal `off` starts
//! with no key at all, as amallo does when the endpoint is disabled.
//!
//! A third argument exercises the in-place rekey (spec §11.3): after a
//! short delay the key is republished as that value — or withdrawn
//! entirely, if it is the literal `off` — on the live connection, with no
//! reconnect. The paired session must survive it.
//!
//! Starting `off` and rekeying *to* a key is the one case a rekey cannot
//! carry, since the HTTP lane is created by the hello: the connection
//! ends with `ConnEnd::Redial` and the loop below redials, mirroring
//! `relay::supervise`. That is what makes enabling the endpoint in the
//! app take effect without a manual disconnect.
//!
//! Pairing material is random per run, which is what you want for a
//! one-shot check — but not for verifying anything about *reconnecting*,
//! where the agent has to come back as the same pair the browser is still
//! waiting on. Set `AMALLO_SMOKE_PAIR_ID` and `AMALLO_SMOKE_PSK`
//! (base64url, no padding) to pin them across restarts.
//!
//! Not wired into any build/test target — run directly:
//!   cargo run --bin relay_smoke [relay_url] [api_key|off] [rekey_to|off]

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
        .unwrap_or_else(|| "wss://relay.41tunnels.com".to_string());
    // `off` means "start as amallo does with the endpoint disabled": no
    // key, so the hello omits `mode:"dual"` and the socket gets no HTTP
    // lane.
    let api_key = std::env::args().nth(2).filter(|k| k != "off");

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let pair_id: [u8; 16] = match std::env::var("AMALLO_SMOKE_PAIR_ID") {
        Ok(v) => b64
            .decode(&v)
            .ok()
            .and_then(|b| b.try_into().ok())
            .expect("AMALLO_SMOKE_PAIR_ID must be 16 bytes, base64url without padding"),
        Err(_) => {
            let mut id = [0u8; 16];
            rand::rng().fill_bytes(&mut id);
            id
        }
    };
    let psk: [u8; 32] = match std::env::var("AMALLO_SMOKE_PSK") {
        Ok(v) => b64
            .decode(&v)
            .ok()
            .and_then(|b| b.try_into().ok())
            .expect("AMALLO_SMOKE_PSK must be 32 bytes, base64url without padding"),
        Err(_) => {
            let mut k = [0u8; 32];
            rand::rng().fill_bytes(&mut k);
            k
        }
    };

    eprintln!("relay_smoke: relay={relay_url}");
    eprintln!("relay_smoke: pair_id={}", b64.encode(pair_id));
    eprintln!("relay_smoke: psk={}", b64.encode(psk));
    // The exact string the web client's "paste pairing code" accepts
    // (spec §4.2), so a browser can be attached without a QR scanner.
    eprintln!(
        "relay_smoke: pairing_code=opencharui://pair?v=1&r={}&i={}&k={}",
        relay_url,
        b64.encode(pair_id),
        b64.encode(psk)
    );

    // `/api/tags` is on the E2E allowlist only and `/v1/models` on the
    // HTTP one, so which route answers proves which lane carried the
    // request — and proves the allowlists stayed separate across the
    // shared socket.
    let router = Router::new()
        .route(
            "/api/tags",
            get(|| async { r#"{"models":[{"name":"relay-smoke-test"}]}"# }),
        )
        .route(
            "/v1/models",
            get(|| async { r#"{"object":"list","data":[{"id":"relay-smoke-openai"}]}"# }),
        );

    match &api_key {
        Some(key) => eprintln!("relay_smoke: dual mode, openai base=<relay>/{key}/v1"),
        None => eprintln!("relay_smoke: e2e only (pass an api key as arg 2 for dual mode)"),
    }

    // Dropping the sender when there is nothing to rekey to also exercises
    // the read loop's "no one is publishing keys" path.
    let (key_tx, key_rx) = tokio::sync::watch::channel(api_key);
    match std::env::args().nth(3) {
        Some(next) => {
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                let value = if next == "off" { None } else { Some(next) };
                eprintln!("relay_smoke: rekeying -> {value:?}");
                key_tx.send_replace(value);
                // Hold the sender open; a dropped one closes the watch.
                std::future::pending::<()>().await;
            });
        }
        None => drop(key_tx),
    }

    // A cut-down `relay::supervise`: enough of a loop to follow a
    // `Redial` through, with none of the backoff — a redial is a user
    // action, and this binary is not here to survive a flapping relay.
    loop {
        let result = conn::run_once_with_status(
            &relay_url,
            pair_id,
            psk,
            router.clone(),
            "smoke-bearer".to_string(),
            key_rx.clone(),
            |status| eprintln!("relay_smoke: status -> {status:?}"),
        )
        .await;

        match result {
            Ok(conn::ConnEnd::Redial) => {
                eprintln!("relay_smoke: redialling to publish the openai endpoint");
                continue;
            }
            Ok(conn::ConnEnd::Closed) => eprintln!("relay_smoke: session ended cleanly"),
            Err(e) => eprintln!("relay_smoke: session ended with error: {e}"),
        }
        break;
    }
}
