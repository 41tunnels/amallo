//! The relay client: connects amallo to the OpenCharUI relay server as an
//! outbound WebSocket, and bridges relay-originated requests into the
//! same axum router the local proxy listener serves. See the build
//! plan's Step 4 (this module, plaintext only) and Step 5 (crypto.rs,
//! added next).

pub mod conn;
pub mod crypto;
pub mod dispatch;
pub mod policy;
#[cfg(test)]
mod smoke_test;
pub mod wire;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use base64::Engine;
use rand::Rng;
use tauri::{AppHandle, Manager, Wry};

use crate::state::AppState;

const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_MULTIPLIER: f64 = 1.8;
const BACKOFF_CAP: Duration = Duration::from_secs(30);
/// A connection that stayed up at least this long resets the backoff
/// exponent — a session that ran fine for a while and then dropped is not
/// evidence the relay (or network) is in trouble, so the next reconnect
/// attempt shouldn't inherit a long delay from some earlier flapping.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

/// (Re)starts the relay connection supervisor, gated entirely behind
/// dev-only environment variables:
///
/// - `AMALLO_RELAY_INSECURE=1` — required to opt in; nothing connects
///   without it. Named to match the wire-level meaning (channel 0x01
///   carries unencrypted inner frames) — this MUST NEVER be set against a
///   production relay.
/// - `AMALLO_RELAY_URL` — the relay's base URL, e.g. `ws://127.0.0.1:8080`.
/// - `AMALLO_RELAY_PAIR_ID` — 16 bytes, base64url (no padding) encoded,
///   matching a `pair_id` an external test tool (e.g. the relay repo's
///   `fakeclient`) already knows.
///
/// This exists so Step 4's plaintext bridge is testable end-to-end
/// against a real relay without Step 6's pairing UI existing yet. Every
/// env var here, and the insecure path itself, is deleted by the time
/// ngrok is removed (Step 12) — real pairing (Step 6) replaces it.
pub fn respawn(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>().inner().clone();

    if let Some(task) = state.relay_task.lock().unwrap().take() {
        task.abort();
    }

    let insecure = std::env::var("AMALLO_RELAY_INSECURE").as_deref() == Ok("1");
    if !insecure {
        return Ok(());
    }

    let relay_url = std::env::var("AMALLO_RELAY_URL")
        .map_err(|_| "AMALLO_RELAY_INSECURE=1 requires AMALLO_RELAY_URL".to_string())?;
    let pair_id_b64 = std::env::var("AMALLO_RELAY_PAIR_ID")
        .map_err(|_| "AMALLO_RELAY_INSECURE=1 requires AMALLO_RELAY_PAIR_ID".to_string())?;
    let pair_id = decode_pair_id(&pair_id_b64)?;

    let router = state
        .router
        .get_or_init(|| crate::proxy::build_router(state.clone()))
        .clone();
    let bearer_token = state.bearer_token();

    println!("amallo: relay: insecure dev mode enabled, target={relay_url}");
    let task = tauri::async_runtime::spawn(async move {
        supervise(relay_url, pair_id, router, bearer_token).await;
    });

    *state.relay_task.lock().unwrap() = Some(task);
    Ok(())
}

fn decode_pair_id(s: &str) -> Result<[u8; 16], String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("AMALLO_RELAY_PAIR_ID: invalid base64url: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "AMALLO_RELAY_PAIR_ID must decode to exactly 16 bytes".to_string())
}

/// Reconnect loop: run one connection to completion, then wait with
/// exponential backoff and full jitter before trying again. Never
/// returns — the caller aborts the task (via `relay_task`) to stop it.
async fn supervise(relay_url: String, pair_id: [u8; 16], router: Router, bearer_token: String) {
    let mut backoff = BACKOFF_BASE;
    loop {
        let attempt_start = std::time::Instant::now();
        println!("amallo: relay: connecting to {relay_url}");

        match conn::run_once(&relay_url, pair_id, router.clone(), bearer_token.clone()).await {
            Ok(()) => println!("amallo: relay: connection closed"),
            Err(e) => eprintln!("amallo: relay: connection error: {e}"),
        }

        if attempt_start.elapsed() > BACKOFF_RESET_AFTER {
            backoff = BACKOFF_BASE;
        }

        let jitter: f64 = rand::rng().random_range(0.0..1.0);
        let sleep_for = Duration::from_secs_f64(backoff.as_secs_f64() * jitter);
        println!("amallo: relay: reconnecting in {sleep_for:?}");
        tokio::time::sleep(sleep_for).await;

        let next = backoff.as_secs_f64() * BACKOFF_MULTIPLIER;
        backoff = Duration::from_secs_f64(next.min(BACKOFF_CAP.as_secs_f64()));
    }
}
