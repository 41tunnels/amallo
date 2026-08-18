//! In-app updates from the project's own GitHub releases.
//!
//! Before this existed an installed copy of amallo stayed on whatever
//! version it was downloaded at forever, which is worse than it sounds: a
//! stale amallo degrades the *paired browser* too, not just this machine —
//! web has a user-visible "This Amallo version does not support sync" path
//! for exactly that case. So the check always runs and an available update
//! is always surfaced; `Settings.auto_update` only decides whether
//! installing needs a click.
//!
//! The one hard rule is that an update never interrupts a live session.
//! Installing restarts the app (on Windows the NSIS installer force-exits
//! it), and amallo's whole job is holding the relay socket a phone or
//! browser is talking through. So the automatic path refuses to install
//! while a device is attached and waits for a later tick; see
//! [`UpdateStatus::Deferred`]. An explicit user request is not gated here —
//! the UI warns first, and overriding is the user's call to make.
//!
//! Updates are verified against the pubkey baked into `tauri.conf.json`;
//! tauri-plugin-updater has no way to turn that off. Copies built before
//! this module shipped have no updater and no pubkey, so they cannot
//! self-update — those users reinstall by hand exactly once.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, Wry};
use tauri_plugin_updater::UpdaterExt;

use crate::state::{AppState, RelayStatus, UpdateStatus};
use crate::tray;

/// Long enough that the first check loses the race with startup work that
/// actually matters (opening the store, binding the proxy, dialling the
/// relay) rather than competing with it for the network.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(30);

/// Releases are cut infrequently and nothing here is urgent, so this is
/// about noticing within a working day, not within minutes.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Retry cadence while an update is known but deferred behind a live
/// session — short enough to install soon after the user's device
/// detaches, instead of leaving them on the old version for hours.
const DEFERRED_RETRY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Starts the background update loop. Runs for the lifetime of the app —
/// like `ollama::spawn_monitor`, nothing cancels it, so no handle is kept.
pub fn spawn_monitor(app: &AppHandle<Wry>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(FIRST_CHECK_DELAY).await;
        loop {
            tick(&app).await;
            // A deferred update is the only state that wants to be
            // revisited promptly; everything else can wait for the next
            // ordinary check.
            let interval = match app.state::<Arc<AppState>>().update_status() {
                UpdateStatus::Deferred { .. } => DEFERRED_RETRY_INTERVAL,
                _ => CHECK_INTERVAL,
            };
            tokio::time::sleep(interval).await;
        }
    });
}

/// One pass: look for a newer release and act on what the settings and the
/// live relay session allow.
async fn tick(app: &AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>().inner().clone();

    // A download already running owns the status; a concurrent check must
    // not stomp on it.
    if matches!(state.update_status(), UpdateStatus::Downloading { .. }) {
        return;
    }

    let update = match check(app).await {
        Ok(Some(update)) => update,
        Ok(None) => {
            // Nothing newer. Clear a stale Available/Deferred — this is
            // the path taken after the user updates by hand.
            if !matches!(state.update_status(), UpdateStatus::Idle) {
                set_status(app, UpdateStatus::Idle);
            }
            return;
        }
        Err(message) => {
            // An offline laptop is the ordinary case here, not a fault
            // worth putting in the tray. Log and try again next tick.
            eprintln!("amallo: update check failed: {message}");
            return;
        }
    };

    let version = update.version.clone();

    if !state.settings().auto_update {
        set_status(app, UpdateStatus::Available { version });
        return;
    }

    if state.relay_status() == RelayStatus::Online {
        // A device is mid-session. Note it and try again shortly, rather
        // than pulling the socket out from under them.
        set_status(app, UpdateStatus::Deferred { version });
        return;
    }

    install_update(app, update).await;
}

/// Asks the configured endpoint whether anything newer exists.
///
/// Errors are stringified rather than propagated: every caller either logs
/// them or shows them, and none of them can distinguish the variants
/// usefully.
async fn check(app: &AppHandle<Wry>) -> Result<Option<tauri_plugin_updater::Update>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    updater.check().await.map_err(|e| e.to_string())
}

/// Downloads and installs `update`, then restarts into it.
///
/// Deliberately takes no view on whether installing is a good idea right
/// now — [`tick`] applies the live-session rule before calling this, and
/// the command behind the user-facing button intentionally does not.
async fn install_update(app: &AppHandle<Wry>, update: tauri_plugin_updater::Update) {
    let version = update.version.clone();
    set_status(app, UpdateStatus::Downloading { version: version.clone() });

    if let Err(e) = update.download_and_install(|_, _| {}, || {}).await {
        eprintln!("amallo: update to {version} failed: {e}");
        set_status(app, UpdateStatus::Failed { message: e.to_string() });
        return;
    }

    // Unreachable on Windows in practice: the NSIS installer terminates
    // the app itself, so control does not come back here.
    app.restart();
}

/// Backs the settings window's install button and the tray's update row.
///
/// Unlike the automatic path this installs even with a device attached:
/// both callers warn the user first (the settings window with a confirm,
/// the tray by opening that window instead of acting), so arriving here
/// means the interruption has already been accepted.
pub async fn install_now(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    if matches!(state.update_status(), UpdateStatus::Downloading { .. }) {
        return Err("An update is already downloading.".into());
    }

    // Re-check rather than holding an `Update` from the monitor: the handle
    // carries the download URL and signature, and re-fetching them costs
    // one request against a manifest we already know is reachable.
    match check(app).await? {
        Some(update) => {
            install_update(app, update).await;
            Ok(())
        }
        None => {
            set_status(app, UpdateStatus::Idle);
            Err("No update is available.".into())
        }
    }
}

/// Updates update state everywhere at once: state, tray menu, settings
/// window — the same three places `relay::set_status` keeps in sync.
fn set_status(app: &AppHandle<Wry>, status: UpdateStatus) {
    let state = app.state::<Arc<AppState>>();
    if state.update_status() == status {
        return;
    }
    *state.update_status.write().unwrap() = status.clone();
    tray::refresh_update(app, &status);
    let _ = app.emit("update-status", &status);
}
