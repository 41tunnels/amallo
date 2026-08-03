use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::state::{AppState, RelayStatus};
use crate::{pairing, relay};

pub struct TrayItems {
    pub menu: Menu<Wry>,
    pub copy_lan: MenuItem<Wry>,
    pub relay_status: MenuItem<Wry>,
    pub relay_toggle: MenuItem<Wry>,
}

pub fn build(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let copy_token = MenuItem::with_id(app, "copy_token", "Copy Bearer Token", true, None::<&str>)?;
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

    let menu = Menu::with_items(
        app,
        &[
            &relay_status,
            &relay_toggle,
            &show_pairing_qr,
            &copy_pairing_code,
            &PredefinedMenuItem::separator(app)?,
            &copy_token,
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
        copy_lan,
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

    refresh_relay(app, &RelayStatus::Disabled);
    Ok(())
}

fn on_menu_event(app: &AppHandle<Wry>, id: &str) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    match id {
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
            app.exit(0);
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
    let _ = items.copy_lan.set_enabled(state.settings().bind_lan);

    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(format!("amallo — {status_text}")));
    }
}
