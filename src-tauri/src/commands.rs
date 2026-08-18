use std::sync::Arc;

use tauri::{AppHandle, State, Wry};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::settings::Settings;
use crate::state::{AppState, RelayStatus, UpdateStatus};
use crate::{pairing, proxy, relay, secrets, settings, tray, update};

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
    // Reconnect the relay only if its target or auto-connect preference
    // changed.
    if old.relay_url != new_settings.relay_url || old.auto_connect_relay != new_settings.auto_connect_relay {
        relay::respawn(&app)?;
    } else if old.openai_endpoint_enabled != new_settings.openai_endpoint_enabled {
        // Toggling the endpoint is published to the live connection
        // instead (spec §11.3): both lanes share one socket, so
        // reconnecting to change the hello would drop a paired browser
        // mid-chat over a setting that has nothing to do with it.
        let key = if new_settings.openai_endpoint_enabled {
            Some(secrets::get_or_create_openai_key(&app)?)
        } else {
            None
        };
        state.relay_api_key.send_replace(key);
        // Reads the flag back out of AppState, which the write above has
        // already updated.
        tray::refresh_menu(&app);
    }
    tray::refresh_relay(&app, &state.relay_status());
    Ok(())
}

#[tauri::command]
pub fn get_bearer_token(state: State<'_, Arc<AppState>>) -> String {
    state.bearer_token()
}

#[tauri::command]
pub fn get_update_status(state: State<'_, Arc<AppState>>) -> UpdateStatus {
    state.update_status()
}

/// Installs the available update now, restarting the app into it.
///
/// Does not check whether a device is attached: the settings window
/// confirms that with the user before calling this, and overriding is
/// theirs to decide. The automatic path in `update::tick` is the one that
/// enforces the live-session rule.
#[tauri::command]
pub async fn install_update(app: AppHandle<Wry>) -> Result<(), String> {
    update::install_now(&app).await
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

/// What the settings UI needs to show for the OpenAI-compatible endpoint
/// (spec §11): whether it is on, and the exact two strings a user pastes
/// into another app.
#[derive(serde::Serialize)]
pub struct OpenAiEndpoint {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
}

#[tauri::command]
pub fn get_openai_endpoint(
    app: AppHandle<Wry>,
    state: State<'_, Arc<AppState>>,
) -> Result<OpenAiEndpoint, String> {
    let s = state.settings();
    let api_key = secrets::get_or_create_openai_key(&app)?;
    Ok(OpenAiEndpoint {
        enabled: s.openai_endpoint_enabled,
        base_url: openai_base_url(&s.relay_url, &api_key),
        api_key,
    })
}

/// Issues a fresh API key and republishes its hash to the live relay
/// connection — the moment that lands, every client holding the old key
/// gets a 401 and any request still in flight under it is torn down.
/// This is the revoke button.
///
/// Publishing rather than reconnecting is the point (spec §11.3): the
/// paired browser shares this socket, and revoking an API key is no
/// reason to interrupt someone's chat. If the relay is disconnected the
/// value is simply recorded and the next hello carries it.
#[tauri::command]
pub fn regenerate_openai_key(
    app: AppHandle<Wry>,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let key = secrets::regenerate_openai_key(&app)?;
    if state.settings().openai_endpoint_enabled {
        state.relay_api_key.send_replace(Some(key.clone()));
    }
    Ok(key)
}

/// Builds the base URL a third-party client is configured with. The relay
/// URL is a WebSocket URL; the HTTP endpoint is the same host over plain
/// HTTP(S), with the key as the first path segment.
///
/// The key is embedded here because that form works with every client,
/// including the ones that only accept a base URL. Clients that can send
/// an `Authorization` header may use the key there instead and drop the
/// path segment — the relay accepts both.
pub(crate) fn openai_base_url(relay_url: &str, api_key: &str) -> String {
    let base = relay_url.trim_end_matches('/');
    let http = match base.strip_prefix("wss://") {
        Some(rest) => format!("https://{rest}"),
        None => match base.strip_prefix("ws://") {
            Some(rest) => format!("http://{rest}"),
            None => base.to_string(),
        },
    };
    format!("{http}/{api_key}/v1")
}

#[cfg(test)]
mod tests {
    use super::openai_base_url;

    #[test]
    fn builds_https_base_url_from_wss_relay() {
        assert_eq!(
            openai_base_url("wss://relay.opencharui.com", "41t_abc"),
            "https://relay.opencharui.com/41t_abc/v1"
        );
    }

    #[test]
    fn builds_http_base_url_from_ws_relay_and_trims_slash() {
        assert_eq!(
            openai_base_url("ws://127.0.0.1:8080/", "41t_abc"),
            "http://127.0.0.1:8080/41t_abc/v1"
        );
    }
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
