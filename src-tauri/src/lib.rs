mod api;
mod commands;
mod ollama;
mod pairing;
mod proxy;
pub mod relay;
mod secrets;
mod settings;
pub mod state;
pub mod store;
mod sync;
mod tray;

use std::sync::Arc;

use tauri::{Manager, RunEvent, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

use crate::state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // reqwest and the relay's E2E crypto both use aws-lc-rs; rustls still
    // can't auto-select a provider when more than one crate in the tree
    // could supply one, so this stays as a guarantee against that even
    // though ngrok (the one dependency that used to pull in a competing
    // `ring` provider) is gone.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second launch: surface the settings window of the running instance.
            tray::show_settings_window(app);
        }))
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let bearer_token = secrets::get_or_create_bearer_token(app.handle())
                .map_err(|e| format!("failed to load secrets: {e}"))?;
            let settings = settings::load(app.handle());

            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("could not resolve app data dir: {e}"))?;

            let state = Arc::new(
                AppState::new(bearer_token, settings, app_data_dir)
                    .map_err(|e| format!("failed to open store: {e}"))?,
            );
            api::v1::spawn_maintenance(state.clone());
            app.manage(state);

            proxy::respawn(app.handle())?;
            relay::respawn(app.handle())?;
            tray::build(app.handle())?;
            // After the tray exists: the first probe result lands on the
            // menu rows built above.
            ollama::spawn_monitor(app.handle());

            // Menu-bar-only app: no Dock icon on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the settings window hides it; the tray app keeps running.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_settings,
            commands::save_settings,
            commands::get_bearer_token,
            commands::get_lan_url,
            commands::regenerate_bearer_token,
            commands::copy_to_clipboard,
            commands::get_autostart,
            commands::set_autostart,
            commands::get_relay_status,
            commands::get_pairing_code,
            commands::get_pairing_qr,
            commands::regenerate_pairing,
            commands::connect_relay,
            commands::disconnect_relay,
            commands::get_openai_endpoint,
            commands::regenerate_openai_key,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app, event| {
            // Keep the app alive when all windows are hidden/closed; Quit uses
            // app.exit(0) which carries a code and is allowed through.
            if let RunEvent::ExitRequested { api, code: None, .. } = event {
                api.prevent_exit();
            }
        });
}
