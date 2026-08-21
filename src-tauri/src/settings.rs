use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Wry};
use tauri_plugin_store::StoreExt;

const STORE_FILE: &str = "settings.json";
const KEY: &str = "settings";

/// OpenCharUI's hosted relay — the default `relay_url` for a fresh
/// install. Still overridable per-instance via Settings for anyone
/// self-hosting a relay (see the relay repo's deployment docs).
const DEFAULT_RELAY_URL: &str = "wss://relay.41tunnels.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Local port the auth proxy listens on.
    pub proxy_port: u16,
    /// Bind the proxy to 0.0.0.0 so LAN clients can reach it directly.
    pub bind_lan: bool,
    /// The relay server's base URL (`wss://...`) used for the outbound
    /// pairing connection (spec §3).
    pub relay_url: String,
    /// Connect to the relay automatically on launch, once paired. The
    /// relay path is the happy path (no `OLLAMA_ORIGINS` setup, works
    /// from anywhere), so this defaults to true.
    pub auto_connect_relay: bool,
    /// Expose the OpenAI-compatible HTTP endpoint through the relay (spec
    /// §11), so any OpenAI-compatible app can point at this machine's
    /// Ollama with an API key.
    ///
    /// Defaults to **true**: it is the endpoint most people install Amallo
    /// for, and it is inert until someone holds the API key. The trade it
    /// carries is real — traffic on this path is not end-to-end encrypted
    /// (an arbitrary third-party client has no PSK, so the relay
    /// necessarily sees prompts and completions in plaintext) and anyone
    /// holding the key can use this machine's GPU — so the settings window
    /// states that next to the switch, and the key can be rotated from
    /// there at any time.
    ///
    /// No field-level `#[serde(default)]` here on purpose: that would fill
    /// a missing key with `bool::default()` (false) instead of the
    /// container default below, so an install predating this field would
    /// silently disagree with a fresh one.
    pub openai_endpoint_enabled: bool,

    /// Install an available update on its own, once no device is attached.
    ///
    /// This does **not** gate the update *check* — that always runs, and an
    /// available update is always surfaced in the tray and the settings
    /// window. Turning this off only means the install waits for a click.
    ///
    /// Defaults to **true**, like every other switch here: a signed update
    /// from the project's own release manifest is maintenance, not a
    /// capability the user is granting anyone. A stale amallo degrades the
    /// paired browser too — web surfaces "This Amallo version does not
    /// support sync" against one — so the safe default is staying current.
    pub auto_update: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            proxy_port: 11435,
            bind_lan: false,
            relay_url: DEFAULT_RELAY_URL.to_string(),
            auto_connect_relay: true,
            openai_endpoint_enabled: true,
            auto_update: true,
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
