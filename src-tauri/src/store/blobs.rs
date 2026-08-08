//! Content-addressed blob store. Bytes live on disk, not in SQLite -
//! streaming a large blob out of a mutex-guarded connection would block
//! every document write for the duration; a file handle doesn't. Refcounts
//! and metadata (`blobs`, `record_blobs`) stay in SQLite.

use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, ToSql};

use super::{hash, validate, Store, StoreError};

/// Hard cap on a single blob's size. Also enforced (redundantly, on
/// purpose) by the API layer's `DefaultBodyLimit` before the body is even
/// fully read - this check is what protects any other caller of `put_blob`.
pub const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum BlobError {
    InvalidHash,
    HashMismatch { claimed: String, computed: String },
    TooLarge { size: u64 },
    Io(String),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::InvalidHash => write!(f, "invalid hash"),
            BlobError::HashMismatch { claimed, computed } => {
                write!(f, "hash mismatch: claimed={claimed} computed={computed}")
            }
            BlobError::TooLarge { size } => write!(f, "blob too large: {size} bytes"),
            BlobError::Io(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for BlobError {}

#[derive(Debug, Clone)]
pub struct BlobPutOutcome {
    pub hash: String,
    pub size: u64,
    /// `false` when a blob with this hash was already stored - by
    /// construction the bytes are identical, so this is informational, not
    /// a conflict.
    pub created: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct GcStats {
    pub deleted: i64,
}

/// Two levels of 256-way fanout so no directory exceeds a few thousand
/// entries. No extension, no MIME on disk - MIME lives in the `$blob`
/// reference inside the document, not on the blob itself.
fn blob_path(blob_dir: &Path, hash: &str) -> PathBuf {
    blob_dir.join(&hash[0..2]).join(&hash[2..4]).join(hash)
}

fn random_suffix() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Validates and stores `bytes` under `claimed_hash`. Verification is
/// mandatory, not a convenience check: without it, `PUT` with attacker
/// bytes under a real hash would permanently poison that hash for every
/// device pulling it, and content-addressed stores are never re-verified
/// after the fact.
pub fn put_blob(store: &Store, claimed_hash: &str, bytes: &[u8], now_ms: i64) -> Result<BlobPutOutcome, BlobError> {
    if !validate::valid_hash(claimed_hash) {
        return Err(BlobError::InvalidHash);
    }
    if bytes.len() as u64 > MAX_BLOB_BYTES {
        return Err(BlobError::TooLarge { size: bytes.len() as u64 });
    }
    let computed = hash::sha256_hex(bytes);
    if computed != claimed_hash {
        return Err(BlobError::HashMismatch {
            claimed: claimed_hash.to_string(),
            computed,
        });
    }

    let final_path = blob_path(&store.blob_dir, claimed_hash);
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BlobError::Io(format!("could not create blob dir: {e}")))?;
    }
    let tmp_path = store.blob_dir.join("tmp").join(format!("{}.part", random_suffix()));
    std::fs::write(&tmp_path, bytes).map_err(|e| BlobError::Io(format!("could not write blob: {e}")))?;
    // Renaming over an existing file is safe: by construction (content
    // addressing) the bytes are identical, so concurrent uploads of the
    // same hash race harmlessly - same atomic temp+rename discipline the
    // old sync.rs used for its collection files.
    std::fs::rename(&tmp_path, &final_path).map_err(|e| BlobError::Io(format!("could not commit blob: {e}")))?;

    let created = {
        let conn = store.conn.lock().unwrap();
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO blobs (hash, size, created_at) VALUES (?1, ?2, ?3)",
                (claimed_hash, bytes.len() as i64, now_ms),
            )
            .map_err(|e| BlobError::Io(e.to_string()))?;
        changed > 0
    };

    Ok(BlobPutOutcome {
        hash: claimed_hash.to_string(),
        size: bytes.len() as u64,
        created,
    })
}

/// Bytes for a stored blob, or `None` if absent (unknown hash, or a DB row
/// whose file vanished - both are treated as "not found" rather than an
/// error, so the client's "404 is non-fatal, drop the field" rule applies
/// uniformly).
pub fn read_blob(store: &Store, hash_str: &str) -> Result<Option<Vec<u8>>, StoreError> {
    if !validate::valid_hash(hash_str) {
        return Ok(None);
    }
    let exists = {
        let conn = store.conn.lock().unwrap();
        conn.query_row("SELECT 1 FROM blobs WHERE hash = ?1", [hash_str], |_| Ok(()))
            .optional()?
            .is_some()
    };
    if !exists {
        return Ok(None);
    }
    match std::fs::read(blob_path(&store.blob_dir, hash_str)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError(format!("could not read blob {hash_str}: {e}"))),
    }
}

/// The subset of `hashes` the store does not have. Invalid-format hashes
/// are reported missing too - nothing could ever have been stored under
/// them.
pub fn missing_blobs(store: &Store, hashes: &[String]) -> Result<Vec<String>, StoreError> {
    let conn = store.conn.lock().unwrap();
    let mut out = Vec::new();
    for h in hashes {
        if !validate::valid_hash(h) {
            out.push(h.clone());
            continue;
        }
        let exists = conn
            .query_row("SELECT 1 FROM blobs WHERE hash = ?1", [h], |_| Ok(()))
            .optional()?
            .is_some();
        if !exists {
            out.push(h.clone());
        }
    }
    Ok(out)
}

/// Deletes blobs with zero `record_blobs` references that are older than
/// `grace_ms`. The grace period is essential: a client uploads blobs
/// *before* pushing the document that references them, so between the PUT
/// and the push a legitimate fresh blob has zero references.
///
/// Deletes the DB row before the file: an orphaned file is harmless (the
/// next sweep catches it, and a re-PUT of the same hash renames over it
/// consistently), whereas an orphaned row would be a phantom "already have
/// it" answer to a blob-existence check.
pub fn gc_blobs(store: &Store, grace_ms: i64, now_ms: i64) -> Result<GcStats, StoreError> {
    let cutoff = now_ms - grace_ms;
    let candidates: Vec<String> = {
        let conn = store.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hash FROM blobs WHERE created_at < ?1
             AND hash NOT IN (SELECT hash FROM record_blobs)",
        )?;
        let rows = stmt.query_map([cutoff], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    if candidates.is_empty() {
        return Ok(GcStats { deleted: 0 });
    }

    {
        let conn = store.conn.lock().unwrap();
        let placeholders = (0..candidates.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM blobs WHERE hash IN ({placeholders})");
        let params: Vec<&dyn ToSql> = candidates.iter().map(|h| h as &dyn ToSql).collect();
        conn.execute(&sql, params.as_slice())?;
    }

    for h in &candidates {
        let _ = std::fs::remove_file(blob_path(&store.blob_dir, h));
    }

    Ok(GcStats {
        deleted: candidates.len() as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::records::PushRecord;

    fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        Store::open_in_memory(dir.keep().join("blobs")).unwrap()
    }

    fn hash_of(bytes: &[u8]) -> String {
        hash::sha256_hex(bytes)
    }

    #[test]
    fn mismatched_hash_put_is_rejected() {
        let s = store();
        let bytes = b"avatar bytes";
        let wrong_hash = hash_of(b"different bytes");
        let err = s.put_blob(&wrong_hash, bytes, 1000).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        assert!(s.read_blob(&wrong_hash).unwrap().is_none());
    }

    #[test]
    fn double_put_is_a_noop_second_time() {
        let s = store();
        let bytes = b"avatar bytes";
        let h = hash_of(bytes);
        let first = s.put_blob(&h, bytes, 1000).unwrap();
        assert!(first.created);
        let second = s.put_blob(&h, bytes, 2000).unwrap();
        assert!(!second.created);
        assert_eq!(s.read_blob(&h).unwrap().unwrap(), bytes);
    }

    #[test]
    fn oversized_blob_is_rejected() {
        let s = store();
        let bytes = vec![0u8; (MAX_BLOB_BYTES + 1) as usize];
        let h = hash_of(&bytes);
        let err = s.put_blob(&h, &bytes, 1000).unwrap_err();
        assert!(matches!(err, BlobError::TooLarge { .. }));
    }

    #[test]
    fn blobs_check_returns_exactly_the_missing_set() {
        let s = store();
        let present = hash_of(b"i exist");
        s.put_blob(&present, b"i exist", 1000).unwrap();
        let absent = hash_of(b"i do not exist");

        let missing = s
            .missing_blobs(&[present.clone(), absent.clone()])
            .unwrap();
        assert_eq!(missing, vec![absent]);
    }

    #[test]
    fn push_referencing_absent_blob_is_missing_blobs_and_writes_nothing() {
        let s = store();
        let absent = hash_of(b"never uploaded");
        let body = format!(r#"{{"avatar":{{"$blob":"{absent}","mime":"image/png","size":3}}}}"#);
        let rec = PushRecord {
            namespace: "characters".into(),
            key: "a".into(),
            hash: hash_of(body.as_bytes()),
            updated_at: 100,
            deleted: false,
            data: Some(body),
        };
        let out = s.push(vec![rec], 1000).unwrap();
        assert_eq!(out[0].missing_blobs, vec![absent]);
        assert_eq!(s.info().unwrap().head, 0, "nothing should be written");
    }

    #[test]
    fn gc_spares_a_fresh_unreferenced_blob_within_grace() {
        let s = store();
        let h = hash_of(b"fresh");
        s.put_blob(&h, b"fresh", 1_000).unwrap();
        // "now" is only 1ms after creation; grace is 24h - nowhere near reapable.
        let stats = s.gc_blobs(24 * 3_600_000, 1_001).unwrap();
        assert_eq!(stats.deleted, 0);
        assert!(s.read_blob(&h).unwrap().is_some());
    }

    #[test]
    fn gc_reaps_an_aged_unreferenced_blob() {
        let s = store();
        let h = hash_of(b"stale");
        s.put_blob(&h, b"stale", 0).unwrap();
        let stats = s.gc_blobs(1_000, 2_000).unwrap(); // 2000ms later, grace is 1000ms
        assert_eq!(stats.deleted, 1);
        assert!(s.read_blob(&h).unwrap().is_none());
    }

    #[test]
    fn gc_never_reaps_a_referenced_blob() {
        let s = store();
        let h = hash_of(b"avatar");
        s.put_blob(&h, b"avatar", 0).unwrap();

        let body = format!(r#"{{"avatar":{{"$blob":"{h}","mime":"image/png","size":6}}}}"#);
        let rec = PushRecord {
            namespace: "characters".into(),
            key: "a".into(),
            hash: hash_of(body.as_bytes()),
            updated_at: 100,
            deleted: false,
            data: Some(body),
        };
        assert_eq!(s.push(vec![rec], 0).unwrap()[0].status, crate::store::PushStatus::Applied);

        // Long past any grace period, but still referenced.
        let stats = s.gc_blobs(0, 10_000_000).unwrap();
        assert_eq!(stats.deleted, 0);
        assert!(s.read_blob(&h).unwrap().is_some());
    }

    #[test]
    fn tombstoning_the_referencing_record_makes_its_blob_reapable() {
        let s = store();
        let h = hash_of(b"avatar");
        s.put_blob(&h, b"avatar", 0).unwrap();
        let body = format!(r#"{{"avatar":{{"$blob":"{h}","mime":"image/png","size":6}}}}"#);
        s.push(
            vec![PushRecord {
                namespace: "characters".into(),
                key: "a".into(),
                hash: hash_of(body.as_bytes()),
                updated_at: 100,
                deleted: false,
                data: Some(body),
            }],
            0,
        )
        .unwrap();

        s.push(
            vec![PushRecord {
                namespace: "characters".into(),
                key: "a".into(),
                hash: hash::EMPTY_HASH.to_string(),
                updated_at: 200,
                deleted: true,
                data: None,
            }],
            0,
        )
        .unwrap();

        let stats = s.gc_blobs(0, 10_000_000).unwrap();
        assert_eq!(stats.deleted, 1);
        assert!(s.read_blob(&h).unwrap().is_none());
    }

    #[test]
    fn invalid_hash_download_and_check_are_handled_defensively() {
        let s = store();
        assert!(s.read_blob("not-a-hash").unwrap().is_none());
        let missing = s.missing_blobs(&["not-a-hash".to_string()]).unwrap();
        assert_eq!(missing, vec!["not-a-hash".to_string()]);
    }
}
