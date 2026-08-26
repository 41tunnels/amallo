use std::sync::Arc;

use tauri::menu::{IsMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};

use crate::state::{AppState, OllamaStatus, RelayStatus, UpdateStatus};
use crate::{relay, update};

pub struct TrayItems {
    /// Sits above everything, and only while there is actually an update
    /// (see `build_menu`) — a version the user cannot act on is noise, and
    /// this row outranks status text when it does apply.
    pub update: MenuItem<Wry>,
    pub ollama_status: MenuItem<Wry>,
    pub relay_status: MenuItem<Wry>,
    pub relay_toggle: MenuItem<Wry>,
    pub settings: MenuItem<Wry>,
    pub quit: MenuItem<Wry>,
}

impl TrayItems {
    fn build_menu(&self, app: &AppHandle<Wry>, show_update: bool) -> tauri::Result<Menu<Wry>> {
        let sep_after_update = PredefinedMenuItem::separator(app)?;
        let sep_after_relay = PredefinedMenuItem::separator(app)?;
        let sep_after_settings = PredefinedMenuItem::separator(app)?;
        let sep_before_quit = PredefinedMenuItem::separator(app)?;

        let mut items: Vec<&dyn IsMenuItem<Wry>> = Vec::new();
        if show_update {
            items.push(&self.update);
            items.push(&sep_after_update);
        }
        items.extend([
            &self.ollama_status as &dyn IsMenuItem<Wry>,
            &sep_after_relay,
            &self.relay_status,
            &self.relay_toggle,
        ]);
        items.push(&sep_after_settings);
        items.push(&self.settings);
        items.push(&sep_before_quit);
        items.push(&self.quit);

        Menu::with_items(app, &items)
    }
}

pub fn build(app: &AppHandle<Wry>) -> tauri::Result<()> {
    // Created unconditionally but kept out of the menu until there is an
    // update to offer — a version the user cannot act on is noise. Starts
    // enabled; `refresh_update` disables it while a download is running.
    let update_item = MenuItem::with_id(app, "update", "Update available…", true, None::<&str>)?;
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

    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Amallo", true, None::<&str>)?;

    let state = app.state::<Arc<AppState>>().inner().clone();

    let items = TrayItems {
        update: update_item,
        ollama_status,
        relay_status,
        relay_toggle,
        settings,
        quit,
    };
    // No update is known this early — the first check is 30s out.
    let menu = items.build_menu(app, false)?;
    let _ = state.tray_items.set(items);

    // Both platforms get their own tightly-cropped tray glyph rather than
    // reusing the app icon: the app icon's mark sits well inside its tile
    // (right for a Start Menu/dock tile, matching the design system's
    // "maskable" icon convention), which reads as a speck at actual
    // notification-area size. tray-template.png/tray-icon.png crop to the
    // mark's real bounding box and fill the canvas with it instead.
    //
    // macOS: solid paper-100 glyph on transparent, auto-tint (template
    // mode) deliberately off — see icon_as_template below.
    #[cfg(target_os = "macos")]
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
    // Windows/Linux: no template auto-tint exists, so the glyph gets its
    // own filled paper-100/ink-800 tile instead — self-contained contrast
    // on any taskbar theme.
    #[cfg(not(target_os = "macos"))]
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-icon.png"))?;

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

/// Rebuilds the tray menu so the conditional update row appears only while
/// an update exists. muda has no per-item show/hide, so the menu itself is
/// replaced rather than the item being left in place disabled. The status
/// is read from `AppState`, so callers only have to make sure they have
/// already committed their change there. Cheap and infrequent enough that a
/// full rebuild is the simpler correct choice.
pub fn refresh_menu(app: &AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };
    let show_update = update_text(&state.update_status()).is_some();
    let Ok(menu) = items.build_menu(app, show_update) else {
        return;
    };
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_menu(Some(menu));
    }
}

fn on_menu_event(app: &AppHandle<Wry>, id: &str) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    match id {
        // Two cases hand off to the settings window instead of acting:
        // a device mid-session, because installing restarts the app and
        // that window is where the warning and the choice live; and a
        // previous failure, because the row only has room to say that it
        // failed, not why. Otherwise there is nothing to explain first.
        "update" => {
            let status = state.update_status();
            if state.relay_status() == RelayStatus::Online
                || matches!(status, UpdateStatus::Failed { .. })
            {
                show_settings_window(app);
            } else {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = update::install_now(&app).await {
                        eprintln!("amallo: update: {e}");
                    }
                });
            }
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

/// The update row's label, or `None` when there is no row to show.
///
/// Returning `Option` rather than a plain string is what lets
/// `refresh_menu` decide visibility from the same function that writes the
/// text, so the two can't disagree about whether a row applies.
fn update_text(status: &UpdateStatus) -> Option<String> {
    match status {
        UpdateStatus::Idle => None,
        UpdateStatus::Available { version } => Some(format!("Update to {version}…")),
        // Says what it is waiting for. Still clickable: "waiting" is
        // amallo's own courtesy, and a user who wants it now may say so.
        UpdateStatus::Deferred { version } => {
            Some(format!("Update to {version} — waiting for this session to end"))
        }
        UpdateStatus::Downloading { version } => Some(format!("Downloading {version}…")),
        // No message here: tray rows are one line and an updater error is
        // rarely a sentence worth truncating. The settings window has room.
        UpdateStatus::Failed { .. } => Some("Update failed — open Settings".to_string()),
    }
}

/// Sync the update row with the latest updater state, adding or removing
/// it from the menu as needed.
pub fn refresh_update(app: &AppHandle<Wry>, status: &UpdateStatus) {
    let state = app.state::<Arc<AppState>>();
    let Some(items) = state.tray_items.get() else {
        return;
    };

    if let Some(text) = update_text(status) {
        let _ = items.update.set_text(text);
    }
    // A download is already committed; clicking again would only start a
    // second one.
    let _ = items
        .update
        .set_enabled(!matches!(status, UpdateStatus::Downloading { .. }));

    refresh_menu(app);
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
