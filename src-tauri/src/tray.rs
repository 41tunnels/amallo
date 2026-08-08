use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::state::{AppState, OllamaStatus, RelayStatus};
use crate::{pairing, relay};

pub struct TrayItems {
    pub menu: Menu<Wry>,
    pub ollama_status: MenuItem<Wry>,
    pub relay_status: MenuItem<Wry>,
    pub relay_toggle: MenuItem<Wry>,
}

pub fn build(app: &AppHandle<Wry>) -> tauri::Result<()> {
    // Sits above the relay rows: without a running Ollama there is nothing
    // for the relay to serve, so this is the first thing worth reading.
    let ollama_status = MenuItem::with_id(
        app,
        "ollama_status",
        ollama_text(OllamaStatus::Unknown),
        false,
        None::<&str>,
    )?;
    let relay_status = MenuItem::with_id(app, "relay_status", "Relay: disabled", false, None::<&str>)?;
    let relay_toggle = MenuItem::with_id(app, "relay_toggle", "Connect Relay", true, None::<&str>)?;
    // Opens the settings window — that's where the QR itself renders
    // (a native tray menu item can't show an image); this just gets you
    // there in one click instead of hunting for "Settings…".
    let show_pairing_qr = MenuItem::with_id(app, "show_pairing_qr", "Show Pairing QR…", true, None::<&str>)?;
    let copy_pairing_code = MenuItem::with_id(app, "copy_pairing_code", "Copy Pairing Code", true, None::<&str>)?;

    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Amallo", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &ollama_status,
            &PredefinedMenuItem::separator(app)?,
            &relay_status,
            &relay_toggle,
            &show_pairing_qr,
            &copy_pairing_code,
            &PredefinedMenuItem::separator(app)?,
            &settings,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    let state = app.state::<Arc<AppState>>().inner().clone();
    let _ = state.tray_items.set(TrayItems {
        menu: menu.clone(),
        ollama_status,
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
        .tooltip("Amallo")
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

fn relay_text(status: &RelayStatus) -> (String, &'static str) {
    match status {
        RelayStatus::Disabled => ("Relay: disabled".to_string(), "Connect Relay"),
        RelayStatus::Connecting => ("Relay: connecting…".to_string(), "Disconnect Relay"),
        RelayStatus::Waiting => ("Relay: waiting for a device…".to_string(), "Disconnect Relay"),
        RelayStatus::Online => ("Relay: connected".to_string(), "Disconnect Relay"),
        RelayStatus::Offline => ("Relay: offline, retrying…".to_string(), "Disconnect Relay"),
        RelayStatus::Error { message } => (format!("Relay error: {message}"), "Connect Relay"),
    }
}

fn ollama_text(status: OllamaStatus) -> &'static str {
    match status {
        OllamaStatus::Unknown => "Ollama: checking…",
        OllamaStatus::Up => "Ollama: running",
        // Everything amallo serves is a request Ollama has to answer, so
        // this is a warning, not a status line.
        OllamaStatus::Down => "⚠ Ollama not running — start Ollama",
    }
}

/// Sync the relay tray rows with the relay connection status.
pub fn refresh_relay(app: &AppHandle<Wry>, status: &RelayStatus) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };

    let (status_text, toggle_text) = relay_text(status);
    let _ = items.relay_status.set_text(&status_text);
    let _ = items.relay_toggle.set_text(toggle_text);

    refresh_tooltip(app);
}

/// Sync the Ollama warning row with the latest probe result.
pub fn refresh_ollama(app: &AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };

    let _ = items.ollama_status.set_text(ollama_text(state.ollama_status()));
    refresh_tooltip(app);
}

/// The tooltip is the only surface visible without opening the menu, so a
/// down Ollama gets appended to it rather than replacing the relay status.
fn refresh_tooltip(app: &AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>();
    let (relay, _) = relay_text(&state.relay_status());
    let mut tooltip = format!("Amallo — {relay}");
    if state.ollama_status() == OllamaStatus::Down {
        tooltip.push_str(" · Ollama not running");
    }

    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tooltip));
    }
}
