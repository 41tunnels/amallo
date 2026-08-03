use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Wry};
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "settings.json";
const KEY: &str = "settings";

/// OpenCharUI's hosted relay — the default `relay_url` for a fresh
/// install. Still overridable per-instance via Settings for anyone
/// self-hosting a relay (see the relay repo's deployment docs).
const DEFAULT_RELAY_URL: &str = "wss://amallo-relay.tehfonsi.com";

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
    /// The relay server's base URL (`wss://...`) used for the outbound
    /// pairing connection (spec §3).
    pub relay_url: String,
    /// Connect to the relay automatically on launch, once paired. The
    /// relay path is the happy path (no `OLLAMA_ORIGINS` setup, works
    /// from anywhere) so this defaults to true, unlike
    /// `auto_start_tunnel`.
    pub auto_connect_relay: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            static_domain: None,
            proxy_port: 11435,
            bind_lan: false,
            auto_start_tunnel: false,
            relay_url: DEFAULT_RELAY_URL.to_string(),
            auto_connect_relay: true,
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
