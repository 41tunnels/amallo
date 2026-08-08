use std::sync::Arc;

use tauri::{AppHandle, State, Wry};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::settings::Settings;
use crate::state::{AppState, RelayStatus};
use crate::{pairing, proxy, relay, secrets, settings, tray};

#[tauri::command]
pub fn get_settings(state: State<'_, Arc<AppState>>) -> Settings {
    state.settings()
}

#[tauri::command]
pub fn save_settings(
    app: AppHandle<Wry>,
    state: State<'_, Arc<AppState>>,
    new_settings: Settings,
) -> Result<(), String> {
    let old = state.settings();
    settings::save(&app, &new_settings)?;
    *state.settings.write().unwrap() = new_settings.clone();

    // Rebind the proxy if its listen address changed.
    if old.proxy_port != new_settings.proxy_port || old.bind_lan != new_settings.bind_lan {
        proxy::respawn(&app)?;
    }
    // Reconnect the relay if its target or auto-connect preference changed.
    if old.relay_url != new_settings.relay_url || old.auto_connect_relay != new_settings.auto_connect_relay {
        relay::respawn(&app)?;
    }
    tray::refresh_relay(&app, &state.relay_status());
    Ok(())
}

#[tauri::command]
pub fn get_bearer_token(state: State<'_, Arc<AppState>>) -> String {
    state.bearer_token()
}

#[tauri::command]
pub fn get_lan_url(state: State<'_, Arc<AppState>>) -> String {
    let port = state.settings().proxy_port;
    let ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".into());
    format!("http://{ip}:{port}")
}

#[tauri::command]
pub fn regenerate_bearer_token(
    app: AppHandle<Wry>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let token = secrets::regenerate_bearer_token(&app)?;
    *state.bearer_token.write().unwrap() = token.clone();
    Ok(token)
}

#[tauri::command]
pub fn copy_to_clipboard(app: AppHandle<Wry>, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_autostart(app: AppHandle<Wry>) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_autostart(app: AppHandle<Wry>, enabled: bool) -> Result<(), String> {
    let autolaunch = app.autolaunch();
    if enabled {
        autolaunch.enable().map_err(|e| e.to_string())
    } else {
        autolaunch.disable().map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub fn get_relay_status(state: State<'_, Arc<AppState>>) -> RelayStatus {
    state.relay_status()
}

#[tauri::command]
pub fn get_pairing_code(app: AppHandle<Wry>, state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let (pair_id, psk) = pairing::get_or_create(&app)?;
    Ok(pairing::encode_uri(&state.settings().relay_url, pair_id, psk))
}

#[tauri::command]
pub fn get_pairing_qr(app: AppHandle<Wry>, state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let (pair_id, psk) = pairing::get_or_create(&app)?;
    let uri = pairing::encode_uri(&state.settings().relay_url, pair_id, psk);
    pairing::render_qr_svg(&uri)
}

/// Replaces the pairing material and reconnects immediately — every
/// device paired with the old code loses access at once rather than
/// waiting for the next natural reconnect.
#[tauri::command]
pub fn regenerate_pairing(app: AppHandle<Wry>, state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let (pair_id, psk) = pairing::regenerate(&app)?;
    let uri = pairing::encode_uri(&state.settings().relay_url, pair_id, psk);
    relay::respawn(&app)?;
    Ok(uri)
}

#[tauri::command]
pub fn connect_relay(app: AppHandle<Wry>) -> Result<(), String> {
    relay::connect(&app)
}

#[tauri::command]
pub fn disconnect_relay(app: AppHandle<Wry>) {
    relay::disconnect(&app);
}
