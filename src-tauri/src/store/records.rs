//! Push/pull and the conflict-resolution total order.

use std::cmp::Ordering;
use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension, ToSql, Transaction};

use super::{hash, validate, Store, StoreError};

// --- wire-shaped types (API layer maps these to/from JSON) -----------------

#[derive(Debug, Clone)]
pub struct PushRecord {
    pub namespace: String,
    pub key: String,
    /// Client's claimed SHA-256. Recomputed and checked - see `expected_hash`.
    pub hash: String,
    pub updated_at: i64,
    pub deleted: bool,
    /// Raw JSON text, byte-preserved. `None` iff `deleted`.
    pub data: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushStatus {
    /// Written; seq advanced.
    Applied,
    /// Identical hash already stored. No write, no seq bump - this is what
    /// keeps idempotent re-pushes from causing pull storms on other devices.
    Duplicate,
    /// A different version wins under `wins()`. Not an error; `hash`/`seq`
    /// on the outcome are the WINNER's, so the client acks and stops
    /// retrying rather than fighting the other device.
    Superseded,
    /// One or more referenced blobs are absent. Nothing written; the
    /// client uploads them and re-pushes.
    MissingBlobs,
    /// Hash mismatch, malformed blob ref, or invalid namespace/key.
    Rejected,
}

#[derive(Debug, Clone)]
pub struct PushOutcome {
    pub namespace: String,
    pub key: String,
    pub status: PushStatus,
    /// The seq the store now holds for this key (unchanged for
    /// Duplicate/Superseded/MissingBlobs/Rejected).
    pub seq: i64,
    /// The hash the store now holds (the winner's, for Superseded).
    pub hash: String,
    pub missing_blobs: Vec<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub namespace: String,
    pub key: String,
    pub seq: i64,
    pub hash: String,
    pub updated_at: i64,
    pub deleted: bool,
    /// The stored JSON text, byte-identical to what was pushed. Absent for
    /// tombstones and for `meta_only` pulls.
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PullQuery {
    /// Exclusive lower bound. 0 = from the beginning.
    pub since: i64,
    pub limit: u32,
    /// `None` = every namespace.
    pub namespaces: Option<Vec<String>>,
    /// Omit `data` - a cheap metadata-only reconcile pass.
    pub meta_only: bool,
    /// When present, `since`/`limit`/`namespaces`/`meta_only` are ignored
    /// and exactly these records are returned, with data. Fills gaps found
    /// by a meta_only pass.
    pub keys: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone)]
pub struct PullOutcome {
    pub store_id: String,
    pub head: i64,
    pub reap_floor: i64,
    /// `since` for the next page: max seq in `records`, or `head` when the
    /// page is empty. The client must never derive this itself.
    pub cursor: i64,
    pub more: bool,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone)]
pub struct NamespaceStat {
    pub namespace: String,
    pub live: i64,
    pub deleted: i64,
    pub max_seq: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ReapStats {
    pub floor: i64,
    pub reaped: i64,
}

struct StoredRow {
    seq: i64,
    hash: String,
    updated_at: i64,
    deleted: bool,
}

/// Deterministic total order over competing versions of one key: two
/// devices fed the same pair in either arrival order converge on the same
/// winner, which is what makes this safe without a coordinator.
fn wins(incoming_hash: &str, incoming_updated_at: i64, incoming_deleted: bool, existing: &StoredRow) -> bool {
    // Idempotent re-push: not a conflict, must not bump seq. Callers check
    // this themselves too (to short-circuit before opening a write), but
    // it's repeated here so `wins` is correct in isolation.
    if incoming_hash == existing.hash {
        return false;
    }
    match incoming_updated_at.cmp(&existing.updated_at) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => match (incoming_deleted, existing.deleted) {
            (true, false) => true,  // a delete breaks the tie, deterministically
            (false, true) => false,
            // Same millisecond, different content: pick by hash. Arbitrary,
            // but IDENTICAL on every device - the only property that
            // matters. Without this third key, two devices editing in the
            // same millisecond would each believe they won and ping-pong
            // forever.
            _ => incoming_hash > existing.hash.as_str(),
        },
    }
}

/// The hash a record is expected to carry, given the byte-hash convention:
/// SHA-256 of the raw document bytes for a live record, or the fixed
/// SHA-256("") for a tombstone (which carries no data). The tombstone
/// convention is what makes repeated deletes of the same key idempotent.
fn expected_hash(deleted: bool, data: Option<&str>) -> Result<String, &'static str> {
    match (deleted, data) {
        (true, None) => Ok(hash::EMPTY_HASH.to_string()),
        (true, Some(_)) => Err("tombstone must not carry data"),
        (false, Some(d)) => Ok(hash::sha256_hex(d.as_bytes())),
        (false, None) => Err("live record requires data"),
    }
}

fn walk_blob_refs(value: &serde_json::Value, out: &mut HashSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(h)) = map.get("$blob") {
                out.insert(h.clone());
            }
            for v in map.values() {
                walk_blob_refs(v, out);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                walk_blob_refs(v, out);
            }
        }
        _ => {}
    }
}

fn next_seq(tx: &Transaction) -> Result<i64, StoreError> {
    let seq: i64 = tx.query_row(
        "UPDATE seq_counter SET next = next + 1 WHERE id = 1 RETURNING next - 1",
        [],
        |r| r.get(0),
    )?;
    Ok(seq)
}

fn load_existing(tx: &Transaction, namespace: &str, key: &str) -> Result<Option<StoredRow>, StoreError> {
    tx.query_row(
        "SELECT seq, hash, updated_at, deleted FROM records WHERE namespace = ?1 AND key = ?2",
        (namespace, key),
        |r| {
            Ok(StoredRow {
                seq: r.get(0)?,
                hash: r.get(1)?,
                updated_at: r.get(2)?,
                deleted: r.get::<_, i64>(3)? != 0,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn rejected(namespace: &str, key: &str, message: impl Into<String>) -> PushOutcome {
    PushOutcome {
        namespace: namespace.to_string(),
        key: key.to_string(),
        status: PushStatus::Rejected,
        seq: 0,
        hash: String::new(),
        missing_blobs: Vec::new(),
        message: Some(message.into()),
    }
}

fn push_one(tx: &Transaction, rec: PushRecord, now_ms: i64) -> Result<PushOutcome, StoreError> {
    if !validate::valid_namespace(&rec.namespace) {
        return Ok(rejected(&rec.namespace, &rec.key, "invalid namespace"));
    }
    if !validate::valid_key(&rec.key) {
        return Ok(rejected(&rec.namespace, &rec.key, "invalid key"));
    }
    if !validate::valid_hash(&rec.hash) {
        return Ok(rejected(&rec.namespace, &rec.key, "invalid hash"));
    }

    let expected = match expected_hash(rec.deleted, rec.data.as_deref()) {
        Ok(h) => h,
        Err(msg) => return Ok(rejected(&rec.namespace, &rec.key, msg)),
    };
    if expected != rec.hash {
        return Ok(rejected(
            &rec.namespace,
            &rec.key,
            format!("hash mismatch: claimed={} computed={expected}", rec.hash),
        ));
    }

    // Blob refs: only live records can carry them. Malformed JSON can't
    // actually reach here from the HTTP layer (a `RawValue` is guaranteed
    // syntactically valid), but store-level callers (tests, future
    // internal callers) aren't bound by that, so this stays defensive.
    let mut blob_hashes: HashSet<String> = HashSet::new();
    if let Some(data) = &rec.data {
        let value: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => return Ok(rejected(&rec.namespace, &rec.key, format!("invalid json: {e}"))),
        };
        walk_blob_refs(&value, &mut blob_hashes);
        for h in &blob_hashes {
            if !validate::valid_hash(h) {
                return Ok(rejected(&rec.namespace, &rec.key, format!("malformed blob ref: {h}")));
            }
        }
    }

    if !blob_hashes.is_empty() {
        let mut missing = Vec::new();
        for h in &blob_hashes {
            let exists: bool = tx
                .query_row("SELECT 1 FROM blobs WHERE hash = ?1", [h], |_| Ok(()))
                .optional()?
                .is_some();
            if !exists {
                missing.push(h.clone());
            }
        }
        if !missing.is_empty() {
            missing.sort();
            return Ok(PushOutcome {
                namespace: rec.namespace,
                key: rec.key,
                status: PushStatus::MissingBlobs,
                seq: 0,
                hash: String::new(),
                missing_blobs: missing,
                message: None,
            });
        }
    }

    let existing = load_existing(tx, &rec.namespace, &rec.key)?;

    let should_apply = match &existing {
        None => true,
        Some(row) if row.hash == rec.hash => {
            return Ok(PushOutcome {
                namespace: rec.namespace,
                key: rec.key,
                status: PushStatus::Duplicate,
                seq: row.seq,
                hash: row.hash.clone(),
                missing_blobs: Vec::new(),
                message: None,
            });
        }
        Some(row) => wins(&rec.hash, rec.updated_at, rec.deleted, row),
    };

    if !should_apply {
        let row = existing.expect("superseded implies an existing row");
        return Ok(PushOutcome {
            namespace: rec.namespace,
            key: rec.key,
            status: PushStatus::Superseded,
            seq: row.seq,
            hash: row.hash,
            missing_blobs: Vec::new(),
            message: None,
        });
    }

    let seq = next_seq(tx)?;
    tx.execute(
        "INSERT INTO records (namespace, key, seq, hash, updated_at, deleted, data, server_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(namespace, key) DO UPDATE SET
           seq = excluded.seq, hash = excluded.hash, updated_at = excluded.updated_at,
           deleted = excluded.deleted, data = excluded.data, server_at = excluded.server_at",
        (
            &rec.namespace,
            &rec.key,
            seq,
            &rec.hash,
            rec.updated_at,
            rec.deleted as i64,
            &rec.data,
            now_ms,
        ),
    )?;

    // record_blobs IS the refcount: drop and rebuild for this key from the
    // refs just walked (empty for a tombstone, which cascades away above).
    tx.execute(
        "DELETE FROM record_blobs WHERE namespace = ?1 AND key = ?2",
        (&rec.namespace, &rec.key),
    )?;
    for h in &blob_hashes {
        tx.execute(
            "INSERT OR IGNORE INTO record_blobs (namespace, key, hash) VALUES (?1, ?2, ?3)",
            (&rec.namespace, &rec.key, h),
        )?;
    }

    Ok(PushOutcome {
        namespace: rec.namespace,
        key: rec.key,
        status: PushStatus::Applied,
        seq,
        hash: expected,
        missing_blobs: Vec::new(),
        message: None,
    })
}

pub fn push(store: &Store, records: Vec<PushRecord>, now_ms: i64) -> Result<Vec<PushOutcome>, StoreError> {
    let mut conn = store.conn.lock().unwrap();
    let tx = conn.transaction()?;
    let mut outcomes = Vec::with_capacity(records.len());
    for rec in records {
        outcomes.push(push_one(&tx, rec, now_ms)?);
    }
    tx.commit()?;
    Ok(outcomes)
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<Record> {
    Ok(Record {
        namespace: row.get(0)?,
        key: row.get(1)?,
        seq: row.get(2)?,
        hash: row.get(3)?,
        updated_at: row.get(4)?,
        deleted: row.get::<_, i64>(5)? != 0,
        data: row.get(6)?,
    })
}

pub fn pull(store: &Store, query: PullQuery) -> Result<PullOutcome, StoreError> {
    let conn = store.conn.lock().unwrap();
    let head = Store::head_locked(&conn)?;
    let reap_floor = Store::reap_floor_locked(&conn)?;

    if let Some(keys) = &query.keys {
        let mut stmt = conn.prepare(
            "SELECT namespace, key, seq, hash, updated_at, deleted, data
             FROM records WHERE namespace = ?1 AND key = ?2",
        )?;
        let mut records = Vec::with_capacity(keys.len());
        for (ns, key) in keys {
            if let Some(r) = stmt.query_row((ns, key), row_to_record).optional()? {
                records.push(r);
            }
        }
        return Ok(PullOutcome {
            store_id: store.store_id.clone(),
            head,
            reap_floor,
            cursor: head,
            more: false,
            records,
        });
    }

    let limit = query.limit.max(1) as i64;
    let data_col = if query.meta_only { "NULL" } else { "data" };

    let mut params: Vec<Box<dyn ToSql>> = vec![Box::new(query.since)];
    let sql = match &query.namespaces {
        Some(ns) if !ns.is_empty() => {
            let placeholders = (0..ns.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(",");
            for n in ns {
                params.push(Box::new(n.clone()));
            }
            format!(
                "SELECT namespace, key, seq, hash, updated_at, deleted, {data_col}
                 FROM records WHERE seq > ?1 AND namespace IN ({placeholders})
                 ORDER BY seq ASC LIMIT {}",
                limit + 1
            )
        }
        _ => format!(
            "SELECT namespace, key, seq, hash, updated_at, deleted, {data_col}
             FROM records WHERE seq > ?1 ORDER BY seq ASC LIMIT {}",
            limit + 1
        ),
    };

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let mut rows = stmt.query(param_refs.as_slice())?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(row_to_record(row)?);
    }

    let more = records.len() as i64 > limit;
    if more {
        records.truncate(limit as usize);
    }
    let cursor = records.last().map(|r| r.seq).unwrap_or(head);

    Ok(PullOutcome {
        store_id: store.store_id.clone(),
        head,
        reap_floor,
        cursor,
        more,
        records,
    })
}

pub fn namespace_stats(conn: &Connection) -> Result<Vec<NamespaceStat>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT namespace,
                SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN deleted = 1 THEN 1 ELSE 0 END),
                MAX(seq)
         FROM records GROUP BY namespace ORDER BY namespace",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(NamespaceStat {
            namespace: r.get(0)?,
            live: r.get(1)?,
            deleted: r.get(2)?,
            max_seq: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn record_client_cursor(store: &Store, client_id: &str, cursor: i64, now_ms: i64) -> Result<(), StoreError> {
    let conn = store.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO clients (client_id, last_cursor, last_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT(client_id) DO UPDATE SET last_cursor = excluded.last_cursor, last_seen = excluded.last_seen",
        (client_id, cursor, now_ms),
    )?;
    Ok(())
}

/// Reaps tombstones the whole known fleet has already passed (primary), or
/// that have simply aged past `tombstone_ttl_ms` regardless of any client's
/// cursor (backstop - see the module doc for why both are needed). The
/// floor only ever advances.
pub fn reap_tombstones(
    store: &Store,
    client_retention_ms: i64,
    tombstone_ttl_ms: i64,
    now_ms: i64,
) -> Result<ReapStats, StoreError> {
    let conn = store.conn.lock().unwrap();

    let client_floor: i64 = conn
        .query_row(
            "SELECT MIN(last_cursor) FROM clients WHERE last_seen >= ?1",
            [now_ms - client_retention_ms],
            |r| r.get::<_, Option<i64>>(0),
        )?
        .unwrap_or(0);

    let ttl_floor: i64 = conn
        .query_row(
            "SELECT MAX(seq) FROM records WHERE deleted = 1 AND server_at < ?1",
            [now_ms - tombstone_ttl_ms],
            |r| r.get::<_, Option<i64>>(0),
        )?
        .unwrap_or(0);

    let existing_floor = Store::reap_floor_locked(&conn)?;
    let floor = existing_floor.max(client_floor).max(ttl_floor);

    let reaped = conn.execute("DELETE FROM records WHERE deleted = 1 AND seq <= ?1", [floor])?;
    conn.execute(
        "INSERT INTO meta (k, v) VALUES ('reap_floor', ?1)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        [floor.to_string()],
    )?;

    Ok(ReapStats {
        floor,
        reaped: reaped as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        Store::open_in_memory(dir.keep().join("blobs")).unwrap()
    }

    fn rec(ns: &str, key: &str, body: &str, updated_at: i64) -> PushRecord {
        PushRecord {
            namespace: ns.to_string(),
            key: key.to_string(),
            hash: hash::sha256_hex(body.as_bytes()),
            updated_at,
            deleted: false,
            data: Some(body.to_string()),
        }
    }

    fn tombstone(ns: &str, key: &str, updated_at: i64) -> PushRecord {
        PushRecord {
            namespace: ns.to_string(),
            key: key.to_string(),
            hash: hash::EMPTY_HASH.to_string(),
            updated_at,
            deleted: true,
            data: None,
        }
    }

    // --- ported from sync.rs -------------------------------------------

    #[test]
    fn push_older_is_superseded_and_seq_does_not_advance() {
        let s = store();
        let out1 = s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 1000).unwrap();
        assert_eq!(out1[0].status, PushStatus::Applied);
        let seq_after_first = out1[0].seq;

        let out2 = s.push(vec![rec("characters", "a", r#"{"v":0}"#, 50)], 1001).unwrap();
        assert_eq!(out2[0].status, PushStatus::Superseded);
        assert_eq!(out2[0].seq, seq_after_first, "seq must not advance on a superseded push");

        let info = s.info().unwrap();
        assert_eq!(info.head, seq_after_first, "head must not advance either");
    }

    #[test]
    fn tombstone_wins_tie_direct_unit_test_of_wins() {
        let live = StoredRow { seq: 1, hash: "livehash".into(), updated_at: 100, deleted: false };
        assert!(wins("tombhash", 100, true, &live), "a tombstone at the same updated_at must win");

        let tomb = StoredRow { seq: 1, hash: "tombhash".into(), updated_at: 100, deleted: true };
        assert!(!wins("livehash", 100, false, &tomb), "a live record at the same updated_at must not beat a tombstone");
    }

    #[test]
    fn pull_since_cursor_returns_only_newer_with_paging() {
        let s = store();
        for i in 0..5 {
            s.push(vec![rec("characters", &format!("c{i}"), &format!(r#"{{"n":{i}}}"#), 100 + i)], 1000).unwrap();
        }

        let page1 = s.pull(PullQuery { since: 0, limit: 2, ..Default::default() }).unwrap();
        assert_eq!(page1.records.len(), 2);
        assert!(page1.more);

        let page2 = s.pull(PullQuery { since: page1.cursor, limit: 2, ..Default::default() }).unwrap();
        assert_eq!(page2.records.len(), 2);
        assert!(page2.more);

        let page3 = s.pull(PullQuery { since: page2.cursor, limit: 2, ..Default::default() }).unwrap();
        assert_eq!(page3.records.len(), 1);
        assert!(!page3.more);

        let page4 = s.pull(PullQuery { since: page3.cursor, limit: 2, ..Default::default() }).unwrap();
        assert!(page4.records.is_empty());
        assert!(!page4.more);
        assert_eq!(page4.cursor, page4.head);
    }

    #[test]
    fn store_id_change_forces_full_resync() {
        // Replaces sync.rs's "reports_missing_ids": v1 has no `missing`
        // list, it has store identity instead. A fresh store has a
        // different store_id from any previous one the client might hold.
        let a = store();
        let b = store();
        assert_ne!(a.store_id, b.store_id);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let app_data = dir.path();
        let store_id;
        {
            let s = Store::open(app_data).unwrap();
            s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 1000).unwrap();
            store_id = s.store_id.clone();
        }
        let s2 = Store::open(app_data).unwrap();
        assert_eq!(s2.store_id, store_id);
        let pulled = s2.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pulled.records.len(), 1);
        assert_eq!(pulled.records[0].data.as_deref(), Some(r#"{"v":1}"#));
    }

    // --- new coverage -----------------------------------------------------

    #[test]
    fn hash_mismatch_is_rejected_and_writes_nothing() {
        let s = store();
        let mut bad = rec("characters", "a", r#"{"v":1}"#, 100);
        bad.hash = hash::sha256_hex(b"not the real body");
        let out = s.push(vec![bad], 1000).unwrap();
        assert_eq!(out[0].status, PushStatus::Rejected);
        assert!(out[0].message.as_deref().unwrap().contains("hash mismatch"));
        assert_eq!(s.info().unwrap().head, 0);
    }

    #[test]
    fn identical_repush_is_duplicate_and_seq_is_unchanged() {
        let s = store();
        let out1 = s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 1000).unwrap();
        let seq1 = out1[0].seq;

        // Same content, later updated_at (a pure touch): still a duplicate.
        let out2 = s.push(vec![rec("characters", "a", r#"{"v":1}"#, 999)], 2000).unwrap();
        assert_eq!(out2[0].status, PushStatus::Duplicate);
        assert_eq!(out2[0].seq, seq1);

        let pulled = s.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pulled.records.len(), 1, "a record updated twice appears exactly once in a pull");
    }

    #[test]
    fn convergence_same_pair_either_arrival_order_same_winner() {
        let a = rec("characters", "x", r#"{"v":"a"}"#, 500);
        let b = rec("characters", "x", r#"{"v":"b"}"#, 500); // same updated_at, different content

        let s1 = store();
        s1.push(vec![a.clone()], 1000).unwrap();
        s1.push(vec![b.clone()], 1001).unwrap();
        let final1 = s1.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();

        let s2 = store();
        s2.push(vec![b], 1000).unwrap();
        s2.push(vec![a], 1001).unwrap();
        let final2 = s2.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();

        assert_eq!(final1.records[0].hash, final2.records[0].hash, "arrival order must not change the winner");
    }

    #[test]
    fn tombstone_then_resurrect() {
        let s = store();
        s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 1000).unwrap();
        let del = s.push(vec![tombstone("characters", "a", 200)], 1001).unwrap();
        assert_eq!(del[0].status, PushStatus::Applied);

        let live_again = s.push(vec![rec("characters", "a", r#"{"v":2}"#, 300)], 1002).unwrap();
        assert_eq!(live_again[0].status, PushStatus::Applied);

        let pulled = s.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pulled.records.len(), 1);
        assert!(!pulled.records[0].deleted);
    }

    #[test]
    fn unknown_valid_namespace_pull_is_empty_not_an_error() {
        let s = store();
        let pulled = s
            .pull(PullQuery { since: 0, limit: 10, namespaces: Some(vec!["lorebooks".into()]), ..Default::default() })
            .unwrap();
        assert!(pulled.records.is_empty());
    }

    #[test]
    fn reaping_respects_client_floor_and_ttl_backstop() {
        let s = store();
        s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 1_000).unwrap();
        s.push(vec![tombstone("characters", "a", 200)], 1_000).unwrap();
        let tomb_seq = s.info().unwrap().head;

        // No clients registered yet, tombstone is fresh: nothing reaped.
        let r1 = s.reap_tombstones(90 * 86_400_000, 90 * 86_400_000, 1_000).unwrap();
        assert_eq!(r1.reaped, 0);
        let pulled = s.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();
        assert_eq!(pulled.records.len(), 1);

        // A client whose cursor has passed the tombstone makes it reapable.
        s.record_client_cursor("dev-1", tomb_seq, 1_000).unwrap();
        let r2 = s.reap_tombstones(90 * 86_400_000, 90 * 86_400_000, 1_001).unwrap();
        assert_eq!(r2.reaped, 1);
        let pulled = s.pull(PullQuery { since: 0, limit: 10, ..Default::default() }).unwrap();
        assert!(pulled.records.is_empty());
    }

    #[test]
    fn cursor_below_reap_floor_is_detectable() {
        let s = store();
        s.push(vec![rec("characters", "a", r#"{"v":1}"#, 100)], 0).unwrap();
        s.push(vec![tombstone("characters", "a", 200)], 0).unwrap();
        s.record_client_cursor("dev-1", s.info().unwrap().head, 0).unwrap();
        let r = s.reap_tombstones(0, 0, 1).unwrap();
        assert!(r.floor > 0);
        // The API layer is what turns "since < reap_floor" into a 409; here
        // we just confirm the store publishes a floor a caller can check.
        assert!(s.info().unwrap().reap_floor >= r.floor);
    }
}
