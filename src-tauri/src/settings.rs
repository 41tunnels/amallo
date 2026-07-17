use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Wry};
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "settings.json";
const KEY: &str = "settings";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Optional reserved ngrok domain, e.g. "my-name.ngrok-free.app".
    pub static_domain: Option<String>,
    /// Local port the auth proxy listens on.
    pub proxy_port: u16,
    /// Bind the proxy to 0.0.0.0 so LAN clients can reach it directly.
    pub bind_lan: bool,
    /// Start the ngrok tunnel automatically when the app launches.
    pub auto_start_tunnel: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            static_domain: None,
            proxy_port: 11435,
            bind_lan: false,
            auto_start_tunnel: false,
        }
    }
}

pub fn load(app: &AppHandle<Wry>) -> Settings {
    let Ok(store) = app.store(STORE_FILE) else {
        return Settings::default();
    };
    store
        .get(KEY)
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub fn save(app: &AppHandle<Wry>, settings: &Settings) -> Result<(), String> {
    let store = app.store(STORE_FILE).map_err(|e| e.to_string())?;
    store.set(KEY, serde_json::to_value(settings).map_err(|e| e.to_string())?);
    store.save().map_err(|e| e.to_string())
}
