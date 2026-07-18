use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};

use serde::Serialize;

use crate::settings::Settings;
use crate::sync::SyncStore;
use crate::tray::TrayItems;
use crate::tunnel::TunnelHandle;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum TunnelStatus {
    Stopped,
    Connecting,
    Running { url: String },
    Error { message: String },
}

pub struct AppState {
    /// Bearer token the proxy expects. Kept in memory, persisted in the OS keychain.
    pub bearer_token: RwLock<String>,
    /// Non-secret settings, persisted via tauri-plugin-store.
    pub settings: RwLock<Settings>,
    /// Active ngrok session/forwarder, if any.
    pub tunnel: tokio::sync::Mutex<Option<TunnelHandle>>,
    pub status: RwLock<TunnelStatus>,
    /// Handle of the running proxy server task (aborted on proxy restart).
    pub proxy_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// Menu item handles for live tray updates.
    pub tray_items: OnceLock<TrayItems>,
    /// Document store backing the `/amallo/sync/*` endpoints.
    pub sync: SyncStore,
}

impl AppState {
    pub fn new(bearer_token: String, settings: Settings, sync_dir: PathBuf) -> Self {
        Self {
            bearer_token: RwLock::new(bearer_token),
            settings: RwLock::new(settings),
            tunnel: tokio::sync::Mutex::new(None),
            status: RwLock::new(TunnelStatus::Stopped),
            proxy_task: Mutex::new(None),
            tray_items: OnceLock::new(),
            sync: SyncStore::new(sync_dir),
        }
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.read().unwrap().clone()
    }

    pub fn bearer_token(&self) -> String {
        self.bearer_token.read().unwrap().clone()
    }

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap().clone()
    }
}
