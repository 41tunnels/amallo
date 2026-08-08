use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};

use axum::Router;
use serde::Serialize;

use crate::settings::Settings;
use crate::store::Store;
use crate::sync::SyncStore;
use crate::tray::TrayItems;

/// Mirrors web's `RelayState` (`connecting`/`waiting`/`online`/`offline`)
/// with two amallo-specific additions: `Disabled` (not paired, or
/// `auto_connect_relay` is off — never attempted a connection) and
/// `Error` (a hard failure, e.g. a rejected pairing, distinct from the
/// ordinary retry-with-backoff `Offline` state).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum RelayStatus {
    Disabled,
    Connecting,
    /// Connected to the relay and past hello_ok, but no web peer has
    /// attached to this pair yet.
    Waiting,
    Online,
    Offline,
    Error { message: String },
}

/// Whether the local Ollama the proxy forwards to answers — probed in the
/// background by `ollama::spawn_monitor`. `Unknown` until the first probe
/// completes, so the tray never claims Ollama is down before anything has
/// actually looked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OllamaStatus {
    Unknown,
    Up,
    Down,
}

pub struct AppState {
    /// Bearer token the proxy expects. Kept in memory, persisted to `secrets.json`
    /// (0600) in the app data dir — see `secrets.rs`.
    pub bearer_token: RwLock<String>,
    /// Non-secret settings, persisted via tauri-plugin-store.
    pub settings: RwLock<Settings>,
    /// Live relay connection status — see `relay::set_status`.
    pub relay_status: RwLock<RelayStatus>,
    /// Live local-Ollama reachability — see `ollama::spawn_monitor`.
    pub ollama_status: RwLock<OllamaStatus>,
    /// Handle of the running proxy server task (aborted on proxy restart).
    pub proxy_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Handle of the running relay connection supervisor (aborted and
    /// replaced by `relay::respawn`).
    pub relay_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// The shared axum router both the local proxy listener and the relay
    /// dispatcher serve. Built once (see `proxy::build_router`) rather
    /// than per-listener-restart: `proxy::respawn`'s previous behavior of
    /// constructing a fresh `reqwest::Client` (and thus a fresh
    /// connection pool) on every port/bind-setting change was already a
    /// latent inefficiency; sharing one router with the relay path makes
    /// that the same bug twice if left unfixed, so this fixes both at
    /// once.
    pub router: OnceLock<Router>,
    /// Menu item handles for live tray updates.
    pub tray_items: OnceLock<TrayItems>,
    /// Legacy document store backing `/amallo/sync/*` - kept alive
    /// alongside `store` until a release removes the old endpoints
    /// entirely (see `store::retire_legacy_sync_dir`).
    pub sync: SyncStore,
    /// Generic keyed document + blob store backing `/extended/v1/*`.
    pub store: Store,
}

impl AppState {
    /// `app_data_dir` is the Tauri app data directory. Both the legacy
    /// per-collection JSON store and the new SQLite store live under it
    /// (`sync/` and `store/` respectively) so they can coexist during the
    /// migration window without either being moved out from under the
    /// other - see `Store::open`'s doc comment.
    pub fn new(bearer_token: String, settings: Settings, app_data_dir: PathBuf) -> Result<Self, String> {
        let sync_dir = app_data_dir.join("sync");
        let store = Store::open(&app_data_dir).map_err(|e| e.to_string())?;
        Ok(Self {
            bearer_token: RwLock::new(bearer_token),
            settings: RwLock::new(settings),
            relay_status: RwLock::new(RelayStatus::Disabled),
            ollama_status: RwLock::new(OllamaStatus::Unknown),
            proxy_task: Mutex::new(None),
            relay_task: Mutex::new(None),
            router: OnceLock::new(),
            tray_items: OnceLock::new(),
            sync: SyncStore::new(sync_dir),
            store,
        })
    }

    pub fn relay_status(&self) -> RelayStatus {
        self.relay_status.read().unwrap().clone()
    }

    pub fn ollama_status(&self) -> OllamaStatus {
        *self.ollama_status.read().unwrap()
    }

    pub fn bearer_token(&self) -> String {
        self.bearer_token.read().unwrap().clone()
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }
}
