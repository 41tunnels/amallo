use std::sync::Arc;

use tauri::{AppHandle, State, Wry};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::settings::Settings;
use crate::state::{AppState, TunnelStatus};
use crate::{proxy, secrets, settings, tray, tunnel};

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
    tray::refresh(&app, &state.status());
    Ok(())
}

#[tauri::command]
pub fn set_ngrok_token(app: AppHandle<Wry>, token: String) -> Result<(), String> {
    secrets::set_ngrok_token(&app, token.trim())
}

#[tauri::command]
pub fn has_ngrok_token(app: AppHandle<Wry>) -> Result<bool, String> {
    Ok(secrets::get_ngrok_token(&app)?.is_some())
}

#[tauri::command]
pub fn get_bearer_token(state: State<'_, Arc<AppState>>) -> String {
    state.bearer_token()
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
pub fn get_status(state: State<'_, Arc<AppState>>) -> TunnelStatus {
    state.status()
}

#[tauri::command]
pub async fn start_tunnel(app: AppHandle<Wry>) {
    tunnel::start(app).await;
}

#[tauri::command]
pub async fn stop_tunnel(app: AppHandle<Wry>) {
    tunnel::stop(app).await;
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
