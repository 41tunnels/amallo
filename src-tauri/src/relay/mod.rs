//! The relay client: connects amallo to the OpenCharUI relay server as an
//! outbound WebSocket, and bridges relay-originated requests into the
//! same axum router the local proxy listener serves. Two paths coexist:
//! the real, encrypted path (`conn::run_once`, spec §4-§6) driven by
//! amallo's own pairing material and `Settings.relay_url`/
//! `auto_connect_relay`, and Step 4's plaintext dev bridge
//! (`conn::run_once_insecure`), reachable only via
//! `AMALLO_RELAY_INSECURE=1` and never used against a production relay.
//!
//! There is exactly one supervised connection. The OpenAI-compatible
//! endpoint (spec §11) rides the same socket as a second lane rather than
//! dialling its own — see `conn`'s module docs. That is why enabling or
//! disabling it, or rotating its key, currently goes through `respawn`:
//! the token hash is published in the hello, so changing it means a new
//! hello. Making that in-place is the next phase's job.

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
use tauri::{AppHandle, Emitter, Manager, Wry};
use tokio::sync::watch;

use crate::state::{AppState, RelayStatus};
use crate::{pairing, secrets, tray};

const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_MULTIPLIER: f64 = 1.8;
const BACKOFF_CAP: Duration = Duration::from_secs(30);
/// A connection that stayed up at least this long resets the backoff
/// exponent — a session that ran fine for a while and then dropped is not
/// evidence the relay (or network) is in trouble, so the next reconnect
/// attempt shouldn't inherit a long delay from some earlier flapping.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);

/// Updates relay status everywhere at once: state, tray menu, settings
/// window.
pub(crate) fn set_status(app: &AppHandle<Wry>, status: RelayStatus) {
    if let RelayStatus::Error { message } = &status {
        eprintln!("amallo: relay: error: {message}");
    }
    let state = app.state::<Arc<AppState>>();
    *state.relay_status.write().unwrap() = status.clone();
    tray::refresh_relay(app, &status);
    let _ = app.emit("relay-status", &status);
}

/// (Re)starts the relay connection supervisor from current settings —
/// called at startup and whenever settings that affect it change
/// (`relay_url`, `auto_connect_relay`). Respects `auto_connect_relay`:
/// use [`connect`] for an explicit user action that should connect
/// regardless of that setting.
pub fn respawn(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>().inner().clone();

    if let Some(task) = state.relay_task.lock().unwrap().take() {
        task.abort();
    }

    if std::env::var("AMALLO_RELAY_INSECURE").as_deref() == Ok("1") {
        return spawn_insecure(&state);
    }

    if !state.settings().auto_connect_relay {
        set_status(app, RelayStatus::Disabled);
        return Ok(());
    }

    spawn_real(app, &state)
}

/// Forces a connection attempt regardless of `auto_connect_relay` —
/// backs the tray/settings "Connect Relay" action. Does not change the
/// persisted setting; "connect automatically on launch" is the separate
/// checkbox.
pub fn connect(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    if let Some(task) = state.relay_task.lock().unwrap().take() {
        task.abort();
    }
    spawn_real(app, &state)
}

/// Stops the relay connection supervisor — backs the tray/settings
/// "Disconnect Relay" action. This now stops the OpenAI endpoint too:
/// both lanes share one socket, so disconnecting the relay disconnects
/// everything that rides it.
pub fn disconnect(app: &AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    if let Some(task) = state.relay_task.lock().unwrap().take() {
        task.abort();
    }
    set_status(app, RelayStatus::Disabled);
}

fn spawn_real(app: &AppHandle<Wry>, state: &Arc<AppState>) -> Result<(), String> {
    let router = state
        .router
        .get_or_init(|| crate::proxy::build_router(state.clone()))
        .clone();
    let bearer_token = state.bearer_token();
    let (pair_id, psk) = pairing::get_or_create(app)?;
    let relay_url = state.settings().relay_url;
    // Only materialised when the endpoint is actually switched on, so a
    // user who never enables it never has a key generated at all — and
    // the hello stays byte-identical to the pre-merge one.
    let api_key = if state.settings().openai_endpoint_enabled {
        println!("amallo: relay: OpenAI endpoint enabled, publishing its token hash");
        Some(secrets::get_or_create_openai_key(app)?)
    } else {
        None
    };
    // Seeded before subscribing so the connection's hello sees the
    // current value and its watch arm only fires on later changes.
    state.relay_api_key.send_replace(api_key);
    let api_key_rx = state.relay_api_key.subscribe();

    set_status(app, RelayStatus::Connecting);
    let app_clone = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        supervise(app_clone, relay_url, pair_id, psk, router, bearer_token, api_key_rx).await;
    });
    *state.relay_task.lock().unwrap() = Some(task);
    Ok(())
}

/// Step 4's plaintext dev bridge, gated entirely behind dev-only
/// environment variables:
///
/// - `AMALLO_RELAY_INSECURE=1` — required to opt in; nothing connects
///   without it. Named to match the wire-level meaning (channel 0x01
///   carries unencrypted inner frames) — this MUST NEVER be set against a
///   production relay.
/// - `AMALLO_RELAY_URL` — the relay's base URL, e.g. `ws://127.0.0.1:8080`.
/// - `AMALLO_RELAY_PAIR_ID` — 16 bytes, base64url (no padding) encoded,
///   matching a `pair_id` an external test tool (e.g. the relay repo's
///   `fakeclient`) already knows.
fn spawn_insecure(state: &Arc<AppState>) -> Result<(), String> {
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
        supervise_insecure(relay_url, pair_id, router, bearer_token).await;
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

async fn backoff_sleep(backoff: &mut Duration, attempt_start: std::time::Instant) {
    if attempt_start.elapsed() > BACKOFF_RESET_AFTER {
        *backoff = BACKOFF_BASE;
    }
    let jitter: f64 = rand::rng().random_range(0.0..1.0);
    let sleep_for = Duration::from_secs_f64(backoff.as_secs_f64() * jitter);
    println!("amallo: relay: reconnecting in {sleep_for:?}");
    tokio::time::sleep(sleep_for).await;
    let next = backoff.as_secs_f64() * BACKOFF_MULTIPLIER;
    *backoff = Duration::from_secs_f64(next.min(BACKOFF_CAP.as_secs_f64()));
}

/// Reconnect loop for the real, encrypted path: run one connection to
/// completion, report status transitions, then wait with exponential
/// backoff and full jitter before trying again. Never returns — the
/// caller aborts the task (via `relay_task`) to stop it.
async fn supervise(
    app: AppHandle<Wry>,
    relay_url: String,
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: Router,
    bearer_token: String,
    api_key_rx: watch::Receiver<Option<String>>,
) {
    let mut backoff = BACKOFF_BASE;
    loop {
        let attempt_start = std::time::Instant::now();
        set_status(&app, RelayStatus::Connecting);
        println!("amallo: relay: connecting to {relay_url}");

        let attempt = conn::run_once(
            &app,
            &relay_url,
            pair_id,
            psk,
            router.clone(),
            bearer_token.clone(),
            api_key_rx.clone(),
        );
        match attempt.await {
            Ok(()) => println!("amallo: relay: connection closed"),
            Err(e) => eprintln!("amallo: relay: connection error: {e}"),
        }
        set_status(&app, RelayStatus::Offline);

        backoff_sleep(&mut backoff, attempt_start).await;
    }
}

/// Reconnect loop for the plaintext dev bridge — unchanged from Step 4
/// except sharing `backoff_sleep` with the real path's loop above.
async fn supervise_insecure(relay_url: String, pair_id: [u8; 16], router: Router, bearer_token: String) {
    let mut backoff = BACKOFF_BASE;
    loop {
        let attempt_start = std::time::Instant::now();
        println!("amallo: relay: connecting to {relay_url}");

        match conn::run_once_insecure(&relay_url, pair_id, router.clone(), bearer_token.clone()).await {
            Ok(()) => println!("amallo: relay: connection closed"),
            Err(e) => eprintln!("amallo: relay: connection error: {e}"),
        }

        backoff_sleep(&mut backoff, attempt_start).await;
    }
}
