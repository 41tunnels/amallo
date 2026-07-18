mod commands;
mod proxy;
mod secrets;
mod settings;
mod state;
mod sync;
mod tray;
mod tunnel;

use std::sync::Arc;

use tauri::{Manager, RunEvent, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

use crate::state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Both reqwest (aws-lc-rs) and ngrok (ring) pull in a rustls crypto
    // provider, so rustls can't auto-select one — install it explicitly.
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
            let auto_start_tunnel = settings.auto_start_tunnel;

            let sync_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("could not resolve app data dir: {e}"))?
                .join("sync");

            app.manage(Arc::new(AppState::new(bearer_token, settings, sync_dir)));

            proxy::respawn(app.handle())?;
            tray::build(app.handle())?;

            // Menu-bar-only app: no Dock icon on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            if auto_start_tunnel {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tunnel::start(handle).await;
                });
            }
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
            commands::set_ngrok_token,
            commands::has_ngrok_token,
            commands::get_bearer_token,
            commands::regenerate_bearer_token,
            commands::get_status,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::copy_to_clipboard,
            commands::get_autostart,
            commands::set_autostart,
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
