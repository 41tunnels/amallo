//! Document-sync storage server.
//!
//! In addition to proxying Ollama, amallo stores opaque JSON documents so that
//! several OpenCharUI web clients pointed at the same instance can sync their
//! characters, personas and chats. Records are wrapped in an [`Envelope`] and
//! merged last-write-wins by `updated_at`; the `data` payload is never
//! inspected. One JSON file per collection lives under `<app_data>/sync/`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::proxy::ProxyCtx;

/// Collections a client may sync. Anything else is a 404 — keeps arbitrary
/// files from being created under the sync dir.
const COLLECTIONS: &[&str] = &["characters", "personas", "chats"];

/// One synced record. `data` is the full client-side document (opaque here);
/// it is `None` for tombstones (`deleted = true`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Client → server: records changed locally, plus the id→updatedAt of every
/// record the client already holds (so the server only returns newer ones and
/// never re-ships unchanged payloads such as avatars).
#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub records: Vec<Envelope>,
    #[serde(default)]
    pub known: HashMap<String, i64>,
}

/// Server → client: records newer than the client's `known` map, and the ids
/// the client knows that the server is missing entirely (fresh/wiped server) so
/// the client can push them back.
#[derive(Debug, Serialize)]
pub struct SyncResponse {
    pub records: Vec<Envelope>,
    pub missing: Vec<String>,
}

/// Returns true when `incoming` should replace `existing`: strictly newer, or
/// same timestamp with a tombstone (deletes break ties, deterministically).
fn wins(incoming: &Envelope, existing: &Envelope) -> bool {
    incoming.updated_at > existing.updated_at
        || (incoming.updated_at == existing.updated_at && incoming.deleted && !existing.deleted)
}

/// Filesystem-backed store, one JSON file per collection. A single mutex
/// serialises the read-modify-write cycle since axum handlers run concurrently.
pub struct SyncStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl SyncStore {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            lock: Mutex::new(()),
        }
    }

    fn collection_path(&self, collection: &str) -> PathBuf {
        self.dir.join(format!("{collection}.json"))
    }

    fn load_map(path: &Path) -> Result<HashMap<String, Envelope>, String> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("sync store {path:?} is corrupt: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(format!("could not read sync store {path:?}: {e}")),
        }
    }

    /// Atomic write: serialise to a sibling temp file, then rename over the
    /// target (same directory → same filesystem → atomic replace).
    fn store_map(path: &Path, map: &HashMap<String, Envelope>) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("could not create sync dir: {e}"))?;
        }
        let json = serde_json::to_vec_pretty(map).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &json).map_err(|e| format!("could not write sync store: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("could not commit sync store: {e}"))?;
        Ok(())
    }

    /// Merge `req.records` into the collection and return everything newer than
    /// the client's `known` map plus the ids the server is missing.
    pub fn exchange(&self, collection: &str, req: SyncRequest) -> Result<SyncResponse, String> {
        let _guard = self.lock.lock().map_err(|e| e.to_string())?;
        let path = self.collection_path(collection);
        let mut map = Self::load_map(&path)?;

        let mut changed = false;
        for incoming in req.records {
            match map.get(&incoming.id) {
                Some(existing) if !wins(&incoming, existing) => {}
                _ => {
                    map.insert(incoming.id.clone(), incoming);
                    changed = true;
                }
            }
        }

        // Records the client hasn't seen (or has an older copy of).
        let records: Vec<Envelope> = map
            .values()
            .filter(|env| match req.known.get(&env.id) {
                Some(&known_at) => env.updated_at > known_at,
                None => true,
            })
            .cloned()
            .collect();

        // Ids the client holds but the server lost entirely.
        let missing: Vec<String> = req
            .known
            .keys()
            .filter(|id| !map.contains_key(*id))
            .cloned()
            .collect();

        if changed {
            Self::store_map(&path, &map)?;
        }

        Ok(SyncResponse { records, missing })
    }

    /// All envelopes in a collection (tombstones included). Used by the GET
    /// endpoint for debugging and tests.
    pub fn all(&self, collection: &str) -> Result<Vec<Envelope>, String> {
        let _guard = self.lock.lock().map_err(|e| e.to_string())?;
        let map = Self::load_map(&self.collection_path(collection))?;
        Ok(map.into_values().collect())
    }
}

fn is_valid_collection(collection: &str) -> bool {
    COLLECTIONS.contains(&collection)
}

/// `POST /amallo/sync/{collection}` — merge changes and return newer records.
pub async fn sync_post(
    State(ctx): State<ProxyCtx>,
    AxumPath(collection): AxumPath<String>,
    Json(req): Json<SyncRequest>,
) -> Response {
    if !is_valid_collection(&collection) {
        return (StatusCode::NOT_FOUND, "unknown collection\n").into_response();
    }
    let state = ctx.state.clone();
    let result =
        tokio::task::spawn_blocking(move || state.sync.exchange(&collection, req)).await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(msg)) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("sync task failed: {e}\n"),
        )
            .into_response(),
    }
}

/// `GET /amallo/sync/{collection}` — dump all envelopes (debug/tests).
pub async fn sync_get(
    State(ctx): State<ProxyCtx>,
    AxumPath(collection): AxumPath<String>,
) -> Response {
    if !is_valid_collection(&collection) {
        return (StatusCode::NOT_FOUND, "unknown collection\n").into_response();
    }
    let state = ctx.state.clone();
    let result = tokio::task::spawn_blocking(move || state.sync.all(&collection)).await;
    match result {
        Ok(Ok(records)) => Json(SyncResponse {
            records,
            missing: Vec::new(),
        })
        .into_response(),
        Ok(Err(msg)) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("sync task failed: {e}\n"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(id: &str, updated_at: i64) -> Envelope {
        Envelope {
            id: id.to_string(),
            updated_at,
            deleted: false,
            data: Some(serde_json::json!({ "v": updated_at })),
        }
    }

    fn tombstone(id: &str, updated_at: i64) -> Envelope {
        Envelope {
            id: id.to_string(),
            updated_at,
            deleted: true,
            data: None,
        }
    }

    fn store() -> (SyncStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (SyncStore::new(dir.path().to_path_buf()), dir)
    }

    #[test]
    fn newer_wins_older_ignored() {
        let (store, _dir) = store();
        store
            .exchange(
                "characters",
                SyncRequest {
                    records: vec![env("a", 100)],
                    known: HashMap::new(),
                },
            )
            .unwrap();
        // Older push is ignored.
        store
            .exchange(
                "characters",
                SyncRequest {
                    records: vec![env("a", 50)],
                    known: HashMap::new(),
                },
            )
            .unwrap();
        let all = store.all("characters").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].updated_at, 100);

        // Newer push wins.
        store
            .exchange(
                "characters",
                SyncRequest {
                    records: vec![env("a", 200)],
                    known: HashMap::new(),
                },
            )
            .unwrap();
        assert_eq!(store.all("characters").unwrap()[0].updated_at, 200);
    }

    #[test]
    fn tombstone_wins_tie() {
        assert!(wins(&tombstone("a", 100), &env("a", 100)));
        assert!(!wins(&env("a", 100), &tombstone("a", 100)));
    }

    #[test]
    fn returns_only_records_newer_than_known() {
        let (store, _dir) = store();
        store
            .exchange(
                "chats",
                SyncRequest {
                    records: vec![env("a", 100), env("b", 100)],
                    known: HashMap::new(),
                },
            )
            .unwrap();

        // Client knows a@100 but not b → only b comes back.
        let mut known = HashMap::new();
        known.insert("a".to_string(), 100);
        let resp = store
            .exchange(
                "chats",
                SyncRequest {
                    records: vec![],
                    known,
                },
            )
            .unwrap();
        assert_eq!(resp.records.len(), 1);
        assert_eq!(resp.records[0].id, "b");
        assert!(resp.missing.is_empty());
    }

    #[test]
    fn reports_missing_ids() {
        let (store, _dir) = store();
        let mut known = HashMap::new();
        known.insert("gone".to_string(), 100);
        let resp = store
            .exchange(
                "personas",
                SyncRequest {
                    records: vec![],
                    known,
                },
            )
            .unwrap();
        assert_eq!(resp.missing, vec!["gone".to_string()]);
    }

    #[test]
    fn persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = SyncStore::new(dir.path().to_path_buf());
            store
                .exchange(
                    "characters",
                    SyncRequest {
                        records: vec![env("a", 100)],
                        known: HashMap::new(),
                    },
                )
                .unwrap();
        }
        let reopened = SyncStore::new(dir.path().to_path_buf());
        let all = reopened.all("characters").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "a");
    }
}
