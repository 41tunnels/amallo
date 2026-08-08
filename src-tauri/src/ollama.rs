//! Liveness probe for the local Ollama instance the proxy forwards to.
//!
//! amallo is only useful while Ollama is actually running on this machine:
//! every proxied request that arrives while it's down turns into a 502 that
//! the user only sees on the phone that made it, with nothing on the
//! machine hinting at why. The tray menu is the one part of amallo that's
//! always at hand, so a background probe keeps a status row there current.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Manager, Wry};

use crate::proxy::OLLAMA_UPSTREAM;
use crate::state::{AppState, OllamaStatus};
use crate::tray;

/// Ollama answers this even with no models pulled, and — unlike
/// `/api/tags` — it touches no model metadata, so it's cheap to poll.
const PROBE_PATH: &str = "/api/version";

/// A loopback request either connects promptly or isn't going to.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Poll faster while it's down: that's when the user is likely mid-fix
/// (starting Ollama) and watching for the warning to clear.
const INTERVAL_UP: Duration = Duration::from_secs(30);
const INTERVAL_DOWN: Duration = Duration::from_secs(5);

/// Starts the background probe loop. Runs for the lifetime of the app —
/// nothing cancels it, so no task handle is kept.
pub fn spawn_monitor(app: &AppHandle<Wry>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(PROBE_TIMEOUT)
            .build()
            .expect("reqwest client");
        let url = format!("{OLLAMA_UPSTREAM}{PROBE_PATH}");

        loop {
            // Any HTTP answer means something is listening and reachable;
            // the failure this warns about is a refused connection (Ollama
            // not started), not an unhappy status code.
            let status = if client.get(&url).send().await.is_ok() {
                OllamaStatus::Up
            } else {
                OllamaStatus::Down
            };
            set_status(&app, status);

            let interval = match status {
                OllamaStatus::Up => INTERVAL_UP,
                _ => INTERVAL_DOWN,
            };
            tokio::time::sleep(interval).await;
        }
    });
}

/// Records the probe result and syncs the tray, skipping the work when
/// nothing changed — the common case, once every 30s.
fn set_status(app: &AppHandle<Wry>, status: OllamaStatus) {
    let state = app.state::<Arc<AppState>>();
    if state.ollama_status() == status {
        return;
    }
    if status == OllamaStatus::Down {
        eprintln!("amallo: Ollama is not reachable at {OLLAMA_UPSTREAM}");
    }
    *state.ollama_status.write().unwrap() = status;
    tray::refresh_ollama(app);
}
