//! Generic keyed document + blob store backing `/extended/v1`.
//!
//! Replaces the three-collection, timestamp-only `sync.rs` with an
//! arbitrary-namespace SQLite store: any namespace, any key, opaque JSON
//! documents, content-addressed blobs, a server-assigned `seq` for
//! incremental pull, and a content hash (SHA-256 over the document's raw
//! bytes — see `hash`) for change detection and idempotent re-push.
//!
//! Layout on disk, under `<app_data>/store/`:
//!   records.db        SQLite: documents, blob refcounts, client cursors
//!   blobs/<h0><h1>/<h2><h3>/<hash>   content-addressed blob bytes
//!   blobs/tmp/                       in-progress uploads
//!
//! A pre-existing `<app_data>/sync/` (the old per-collection JSON files) is
//! renamed to `<app_data>/sync-legacy-v0/` on first open and never read —
//! see the doc comment on `Store::open` for why migration is deliberately
//! skipped.

pub mod blobs;
pub mod hash;
pub mod records;
pub mod validate;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

pub use blobs::{BlobError, BlobPutOutcome, GcStats};
pub use records::{
    NamespaceStat, PullOutcome, PullQuery, PushOutcome, PushRecord, PushStatus, Record,
};

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct InfoSnapshot {
    pub store_id: String,
    pub head: i64,
    pub reap_floor: i64,
    pub namespaces: Vec<NamespaceStat>,
}

/// SQLite-backed store. A single connection behind a mutex, all access run
/// from `spawn_blocking` by the caller (as the old `sync.rs` handlers
/// already did) — a connection pool buys nothing for a single-user desktop
/// agent with a handful of devices, and WAL serialises writers regardless.
/// WAL still earns its place by letting a read-only connection (or the
/// `sqlite3` CLI, for support) read while a push commits.
pub struct Store {
    conn: Mutex<Connection>,
    blob_dir: PathBuf,
    pub store_id: String,
}

impl Store {
    /// `app_data_dir` is the Tauri app data directory (the same root that
    /// used to hold `sync/`, `secrets.json`, `settings.json`).
    ///
    /// NOTE: this deliberately does NOT touch `<app_data>/sync/` on open.
    /// During the coexistence release (`/amallo/sync/*` alongside
    /// `/extended/v1/*`), the OLD `sync::SyncStore` is still actively
    /// reading and writing that directory - renaming it out from under a
    /// running endpoint would break `/amallo/sync/*` rather than retire it
    /// cleanly. See `retire_legacy_sync_dir`, called only once `sync.rs`
    /// itself is deleted.
    pub fn open(app_data_dir: &Path) -> Result<Self, StoreError> {
        let store_dir = app_data_dir.join("store");
        fs::create_dir_all(&store_dir)
            .map_err(|e| StoreError(format!("could not create store dir: {e}")))?;
        let blob_dir = store_dir.join("blobs");
        fs::create_dir_all(blob_dir.join("tmp"))
            .map_err(|e| StoreError(format!("could not create blob dir: {e}")))?;

        let db_path = store_dir.join("records.db");
        let conn = Connection::open(&db_path)?;
        migrate(&conn)?;
        let store_id = get_or_create_store_id(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            blob_dir,
            store_id,
        })
    }

    /// In-memory store — same schema, no filesystem footprint beyond a
    /// throwaway blob dir the caller supplies. Not `cfg(test)`-gated: both
    /// the unit tests in this module and this crate's `tests/` integration
    /// tests need it, and integration tests only ever see a crate's public,
    /// non-cfg(test) surface.
    pub fn open_in_memory(blob_dir: PathBuf) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        migrate(&conn)?;
        let store_id = get_or_create_store_id(&conn)?;
        fs::create_dir_all(blob_dir.join("tmp")).ok();
        Ok(Self {
            conn: Mutex::new(conn),
            blob_dir,
            store_id,
        })
    }

    fn head_locked(conn: &Connection) -> Result<i64, StoreError> {
        // seq_counter.next - 1, not MAX(seq): tombstone reaping deletes
        // rows, which would make MAX(seq) regress after a reap even though
        // seq itself is still monotonically increasing.
        let next: i64 = conn.query_row("SELECT next FROM seq_counter WHERE id = 1", [], |r| {
            r.get(0)
        })?;
        Ok(next - 1)
    }

    fn reap_floor_locked(conn: &Connection) -> Result<i64, StoreError> {
        let floor: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k = 'reap_floor'", [], |r| r.get(0))
            .ok();
        Ok(floor.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    pub fn info(&self) -> Result<InfoSnapshot, StoreError> {
        let conn = self.conn.lock().unwrap();
        let head = Self::head_locked(&conn)?;
        let reap_floor = Self::reap_floor_locked(&conn)?;
        let namespaces = records::namespace_stats(&conn)?;
        Ok(InfoSnapshot {
            store_id: self.store_id.clone(),
            head,
            reap_floor,
            namespaces,
        })
    }

    /// Merge `records` and return one outcome per record, in the same
    /// order. `now_ms` is the server's accept time (`server_at`), passed in
    /// rather than read from the system clock so tests can control it.
    pub fn push(&self, records: Vec<PushRecord>, now_ms: i64) -> Result<Vec<PushOutcome>, StoreError> {
        records::push(self, records, now_ms)
    }

    /// Records newer than `query.since` (or the fetch-by-key set), plus
    /// paging/store-identity metadata.
    pub fn pull(&self, query: PullQuery) -> Result<PullOutcome, StoreError> {
        records::pull(self, query)
    }

    /// Upserts a device's last-seen pull cursor - the input to tombstone
    /// reaping's primary (per-client-floor) mechanism.
    pub fn record_client_cursor(&self, client_id: &str, cursor: i64, now_ms: i64) -> Result<(), StoreError> {
        records::record_client_cursor(self, client_id, cursor, now_ms)
    }

    /// Deletes tombstones every tracked client has already passed, or that
    /// have simply aged past `tombstone_ttl_ms`. See `records::reap_tombstones`.
    pub fn reap_tombstones(
        &self,
        client_retention_ms: i64,
        tombstone_ttl_ms: i64,
        now_ms: i64,
    ) -> Result<records::ReapStats, StoreError> {
        records::reap_tombstones(self, client_retention_ms, tombstone_ttl_ms, now_ms)
    }

    /// Validates and stores a blob's bytes under its claimed hash.
    pub fn put_blob(&self, claimed_hash: &str, bytes: &[u8], now_ms: i64) -> Result<BlobPutOutcome, BlobError> {
        blobs::put_blob(self, claimed_hash, bytes, now_ms)
    }

    /// Bytes for a stored blob, or `None` if absent.
    pub fn read_blob(&self, hash: &str) -> Result<Option<Vec<u8>>, StoreError> {
        blobs::read_blob(self, hash)
    }

    /// The subset of `hashes` the store does NOT have.
    pub fn missing_blobs(&self, hashes: &[String]) -> Result<Vec<String>, StoreError> {
        blobs::missing_blobs(self, hashes)
    }

    /// Deletes blobs with zero references that are older than `grace_ms`.
    pub fn gc_blobs(&self, grace_ms: i64, now_ms: i64) -> Result<GcStats, StoreError> {
        blobs::gc_blobs(self, grace_ms, now_ms)
    }
}

/// Moves `<app_data>/sync/*.json` (the old per-collection JSON files) out
/// of the way to `<app_data>/sync-legacy-v0/`. Call this once, from the
/// release that deletes `sync.rs` and `/amallo/sync/*` (rollout step 6) -
/// calling it any earlier would yank the directory out from under the
/// still-running old endpoint.
///
/// Existing `<app_data>/sync/*.json` is deliberately not imported into the
/// new store: those envelopes have avatars inlined as base64, so importing
/// them would create ~500 KB document fields on day one, defeating the
/// blob store before the first sync. The client is the source of truth -
/// every device holds a complete replica and re-pushes it with proper blob
/// extraction on first v1 sync. Renaming (rather than deleting, or leaving
/// it in place unreferenced) keeps a manual escape hatch and makes the
/// transition observable in support.
pub fn retire_legacy_sync_dir(app_data_dir: &Path) {
    let legacy = app_data_dir.join("sync");
    if !legacy.is_dir() {
        return;
    }
    let renamed = app_data_dir.join("sync-legacy-v0");
    if renamed.exists() {
        return;
    }
    match fs::rename(&legacy, &renamed) {
        Ok(()) => eprintln!("[store] moved legacy sync dir to {}", renamed.display()),
        Err(e) => eprintln!("[store] could not move legacy sync dir: {e}"),
    }
}

fn get_or_create_store_id(conn: &Connection) -> Result<String, StoreError> {
    let existing: Option<String> = conn
        .query_row("SELECT v FROM meta WHERE k = 'store_id'", [], |r| r.get(0))
        .ok();
    if let Some(id) = existing {
        return Ok(id);
    }
    let id = new_uuid_v4();
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('store_id', ?1)",
        [&id],
    )?;
    Ok(id)
}

/// A minimal UUIDv4 generator so the store doesn't need the `uuid` crate
/// for one identifier minted once per store. `rand` is already a
/// dependency (relay pairing/crypto).
fn new_uuid_v4() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Current epoch-ms wall clock. The store's own methods take `now_ms`
/// explicitly (so unit tests can control it); this is what production
/// callers (the API handlers, the maintenance sweep) pass in.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn migrate(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous  = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;

         CREATE TABLE IF NOT EXISTS meta (
           k TEXT PRIMARY KEY,
           v TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS records (
           namespace  TEXT    NOT NULL,
           key        TEXT    NOT NULL,
           seq        INTEGER NOT NULL,
           hash       TEXT    NOT NULL,
           updated_at INTEGER NOT NULL,
           deleted    INTEGER NOT NULL DEFAULT 0,
           data       TEXT,
           server_at  INTEGER NOT NULL,
           PRIMARY KEY (namespace, key),
           CHECK (deleted IN (0, 1)),
           CHECK ((deleted = 1) = (data IS NULL))
         ) STRICT;

         CREATE UNIQUE INDEX IF NOT EXISTS records_seq    ON records(seq);
         CREATE        INDEX IF NOT EXISTS records_ns_seq ON records(namespace, seq);

         CREATE TABLE IF NOT EXISTS blobs (
           hash       TEXT PRIMARY KEY,
           size       INTEGER NOT NULL,
           created_at INTEGER NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS record_blobs (
           namespace TEXT NOT NULL,
           key       TEXT NOT NULL,
           hash      TEXT NOT NULL,
           PRIMARY KEY (namespace, key, hash),
           FOREIGN KEY (namespace, key) REFERENCES records(namespace, key) ON DELETE CASCADE,
           FOREIGN KEY (hash) REFERENCES blobs(hash)
         ) STRICT;
         CREATE INDEX IF NOT EXISTS record_blobs_hash ON record_blobs(hash);

         CREATE TABLE IF NOT EXISTS clients (
           client_id   TEXT PRIMARY KEY,
           last_cursor INTEGER NOT NULL,
           last_seen   INTEGER NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS seq_counter (
           id   INTEGER PRIMARY KEY CHECK (id = 1),
           next INTEGER NOT NULL
         ) STRICT;
         INSERT OR IGNORE INTO seq_counter (id, next) VALUES (1, 1);

         INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '1');
         INSERT OR IGNORE INTO meta (k, v) VALUES ('reap_floor', '0');
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        Store::open_in_memory(dir.path().join("blobs")).unwrap()
    }

    #[test]
    fn store_id_is_stable_and_uuid_shaped() {
        let s = store();
        let id = s.store_id.clone();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
        // Re-reading from the same connection returns the same id.
        assert_eq!(get_or_create_store_id(&s.conn.lock().unwrap()).unwrap(), id);
    }

    #[test]
    fn info_on_empty_store() {
        let s = store();
        let info = s.info().unwrap();
        assert_eq!(info.head, 0);
        assert_eq!(info.reap_floor, 0);
        assert!(info.namespaces.is_empty());
    }
}
