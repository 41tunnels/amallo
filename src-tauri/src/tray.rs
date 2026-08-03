use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::state::{AppState, RelayStatus, TunnelStatus};
use crate::{pairing, relay, tunnel};

pub struct TrayItems {
    pub menu: Menu<Wry>,
    pub status: MenuItem<Wry>,
    pub url: MenuItem<Wry>,
    pub copy_url: MenuItem<Wry>,
    pub copy_connection: MenuItem<Wry>,
    pub toggle: MenuItem<Wry>,
    pub copy_lan: MenuItem<Wry>,
    /// Whether the URL row is currently in the menu (only while running).
    url_shown: AtomicBool,

    pub relay_status: MenuItem<Wry>,
    pub relay_toggle: MenuItem<Wry>,
}

/// The `{ "url", "api_key" }` connection blob clients can consume.
fn connection_json(url: &str, token: &str) -> String {
    #[derive(serde::Serialize)]
    struct Connection<'a> {
        url: &'a str,
        api_key: &'a str,
    }
    serde_json::to_string_pretty(&Connection {
        url,
        api_key: token,
    })
    .unwrap_or_default()
}

pub fn build(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Tunnel: stopped", false, None::<&str>)?;
    let url = MenuItem::with_id(app, "url", "", false, None::<&str>)?;
    let copy_url = MenuItem::with_id(app, "copy_url", "Copy Public URL", false, None::<&str>)?;
    let copy_token =
        MenuItem::with_id(app, "copy_token", "Copy Bearer Token", true, None::<&str>)?;
    let copy_connection = MenuItem::with_id(
        app,
        "copy_connection",
        "Copy Connection (JSON)",
        false,
        None::<&str>,
    )?;
    let toggle = MenuItem::with_id(app, "toggle", "Start Tunnel", true, None::<&str>)?;
    let copy_lan = MenuItem::with_id(app, "copy_lan", "Copy LAN URL", true, None::<&str>)?;

    let relay_status = MenuItem::with_id(app, "relay_status", "Relay: disabled", false, None::<&str>)?;
    let relay_toggle = MenuItem::with_id(app, "relay_toggle", "Connect Relay", true, None::<&str>)?;
    // Opens the settings window — that's where the QR itself renders
    // (a native tray menu item can't show an image); this just gets you
    // there in one click instead of hunting for "Settings…".
    let show_pairing_qr = MenuItem::with_id(app, "show_pairing_qr", "Show Pairing QR…", true, None::<&str>)?;
    let copy_pairing_code = MenuItem::with_id(app, "copy_pairing_code", "Copy Pairing Code", true, None::<&str>)?;

    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit amallo", true, None::<&str>)?;

    // The `url` row is inserted only while the tunnel is running (see refresh),
    // so a stopped tunnel shows no empty line under the status.
    let menu = Menu::with_items(
        app,
        &[
            &relay_status,
            &relay_toggle,
            &show_pairing_qr,
            &copy_pairing_code,
            &PredefinedMenuItem::separator(app)?,
            &status,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &copy_url,
            &copy_token,
            &copy_connection,
            &copy_lan,
            &PredefinedMenuItem::separator(app)?,
            &settings,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    let state = app.state::<Arc<AppState>>().inner().clone();
    let _ = state.tray_items.set(TrayItems {
        menu: menu.clone(),
        status,
        url,
        copy_url,
        copy_connection,
        toggle,
        copy_lan,
        url_shown: AtomicBool::new(false),
        relay_status,
        relay_toggle,
    });

    // macOS menu bar: solid white alpaca glyph. Other platforms use the app icon.
    #[cfg(target_os = "macos")]
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
    #[cfg(not(target_os = "macos"))]
    let icon = app.default_window_icon().cloned().expect("app icon");

    TrayIconBuilder::with_id("main")
        .icon(icon)
        // false: keep the glyph pure white (template mode would recolor it).
        .icon_as_template(false)
        .tooltip("amallo")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| on_menu_event(app, event.id.as_ref()))
        .build(app)?;

    refresh(app, &TunnelStatus::Stopped);
    Ok(())
}

fn on_menu_event(app: &AppHandle<Wry>, id: &str) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    match id {
        "toggle" => {
            let app = app.clone();
            let status = state.status();
            tauri::async_runtime::spawn(async move {
                match status {
                    TunnelStatus::Running { .. } | TunnelStatus::Connecting => {
                        tunnel::stop(app).await
                    }
                    _ => tunnel::start(app).await,
                }
            });
        }
        "copy_url" => {
            if let TunnelStatus::Running { url } = state.status() {
                let _ = app.clipboard().write_text(url);
            }
        }
        "copy_connection" => {
            if let TunnelStatus::Running { url } = state.status() {
                let json = connection_json(&url, &state.bearer_token());
                let _ = app.clipboard().write_text(json);
            }
        }
        "copy_token" => {
            let _ = app.clipboard().write_text(state.bearer_token());
        }
        "copy_lan" => {
            let port = state.settings().proxy_port;
            let ip = local_ip_address::local_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| "127.0.0.1".into());
            let _ = app.clipboard().write_text(format!("http://{ip}:{port}"));
        }
        "relay_toggle" => {
            let app = app.clone();
            match state.relay_status() {
                RelayStatus::Online | RelayStatus::Waiting | RelayStatus::Connecting => {
                    relay::disconnect(&app);
                }
                _ => {
                    let _ = relay::connect(&app);
                }
            }
        }
        "show_pairing_qr" => show_settings_window(app),
        "copy_pairing_code" => {
            if let Ok((pair_id, psk)) = pairing::get_or_create(app) {
                let uri = pairing::encode_uri(&state.settings().relay_url, pair_id, psk);
                let _ = app.clipboard().write_text(uri);
            }
        }
        "settings" => show_settings_window(app),
        "quit" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                tunnel::stop(app.clone()).await;
                app.exit(0);
            });
        }
        _ => {}
    }
}

pub fn show_settings_window(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Sync tray menu items with the tunnel status.
pub fn refresh(app: &AppHandle<Wry>, status: &TunnelStatus) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };

    let (status_text, url_text, toggle_text, running, toggling) = match status {
        TunnelStatus::Stopped => ("Tunnel: stopped".into(), None, "Start Tunnel", false, true),
        TunnelStatus::Connecting => ("Tunnel: connecting…".into(), None, "Stop Tunnel", false, true),
        TunnelStatus::Running { url } => (
            "Tunnel: online".into(),
            Some(url.clone()),
            "Stop Tunnel",
            true,
            true,
        ),
        TunnelStatus::Error { message } => (
            format!("Tunnel error: {message}"),
            None,
            "Start Tunnel",
            false,
            true,
        ),
    };

    let _ = items.status.set_text(&status_text);

    // Show the URL row only while running; otherwise remove it so there's no
    // blank line under the status.
    match &url_text {
        Some(url) => {
            let _ = items.url.set_text(url);
            if !items.url_shown.swap(true, Ordering::Relaxed) {
                // Index 6: relay_status, relay_toggle, show_pairing_qr,
                // copy_pairing_code, separator, status — url goes right
                // after status.
                let _ = items.menu.insert(&items.url, 6);
            }
        }
        None => {
            if items.url_shown.swap(false, Ordering::Relaxed) {
                let _ = items.menu.remove(&items.url);
            }
        }
    }

    let _ = items.copy_url.set_enabled(running);
    let _ = items.copy_connection.set_enabled(running);
    let _ = items.toggle.set_text(toggle_text);
    let _ = items.toggle.set_enabled(toggling);
    let _ = items.copy_lan.set_enabled(state.settings().bind_lan);

    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(match status {
            TunnelStatus::Running { url } => format!("amallo — {url}"),
            _ => format!("amallo — {status_text}"),
        }));
    }
}

/// Sync the relay tray rows with the relay connection status.
pub fn refresh_relay(app: &AppHandle<Wry>, status: &RelayStatus) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };

    let (status_text, toggle_text) = match status {
        RelayStatus::Disabled => ("Relay: disabled".to_string(), "Connect Relay"),
        RelayStatus::Connecting => ("Relay: connecting…".to_string(), "Disconnect Relay"),
        RelayStatus::Waiting => ("Relay: waiting for a device…".to_string(), "Disconnect Relay"),
        RelayStatus::Online => ("Relay: connected".to_string(), "Disconnect Relay"),
        RelayStatus::Offline => ("Relay: offline, retrying…".to_string(), "Disconnect Relay"),
        RelayStatus::Error { message } => (format!("Relay error: {message}"), "Connect Relay"),
    };

    let _ = items.relay_status.set_text(&status_text);
    let _ = items.relay_toggle.set_text(toggle_text);
}

#[cfg(test)]
mod tests {
    use super::connection_json;

    #[test]
    fn connection_json_shape() {
        let json = connection_json("https://abc.ngrok-free.app", "tok\"en");
        // url comes first, api_key second
        assert!(json.find("url").unwrap() < json.find("api_key").unwrap());
        // values present and properly escaped
        assert!(json.contains("\"url\": \"https://abc.ngrok-free.app\""));
        assert!(json.contains("\"api_key\": \"tok\\\"en\""));
        // valid JSON round-trips
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["url"], "https://abc.ngrok-free.app");
        assert_eq!(v["api_key"], "tok\"en");
    }
}
