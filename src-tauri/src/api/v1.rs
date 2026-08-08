//! `/extended/v1/*` - the generic keyed document + blob store's wire
//! protocol. Handlers here only translate JSON <-> `crate::store` calls;
//! all merge/hash/conflict logic lives in `store`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::proxy::ProxyCtx;
use crate::state::AppState;
use crate::store::records::{PullQuery, PushRecord, PushStatus};
use crate::store::{blobs::BlobError, now_ms, validate};

pub const PROTOCOL_VERSION: u32 = 1;

const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;
const MAX_BLOB_BYTES: u64 = crate::store::blobs::MAX_BLOB_BYTES;
const MAX_PUSH_RECORDS: usize = 256;
const MAX_PULL_RECORDS: u32 = 256;
const DEFAULT_PULL_LIMIT: u32 = 256;
const MAX_BLOB_CHECK_HASHES: usize = 1024;

/// Tombstone reaping horizons (see `store::records::reap_tombstones`).
const CLIENT_RETENTION_MS: i64 = 90 * 86_400_000;
const TOMBSTONE_TTL_MS: i64 = 90 * 86_400_000;

/// Blob GC's grace period: a client uploads blobs *before* pushing the
/// document that references them, so a freshly-uploaded, still-unreferenced
/// blob must not be reaped out from under that in-flight push.
const BLOB_GC_GRACE_MS: i64 = 24 * 60 * 60 * 1_000;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// Sweeps tombstones and orphaned blobs at startup and every six hours.
/// Runs for the process lifetime; not cancelled on proxy restart (unlike
/// `proxy::respawn`'s task), since a port/bind change has no bearing on the
/// store.
pub fn spawn_maintenance(state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        loop {
            let s = state.clone();
            let result = tokio::task::spawn_blocking(move || {
                let now = now_ms();
                let reap = s.store.reap_tombstones(CLIENT_RETENTION_MS, TOMBSTONE_TTL_MS, now);
                let gc = s.store.gc_blobs(BLOB_GC_GRACE_MS, now);
                (reap, gc)
            })
            .await;

            match result {
                Ok((Ok(reap), Ok(gc))) => {
                    if reap.reaped > 0 || gc.deleted > 0 {
                        println!(
                            "amallo: store maintenance - reaped {} tombstone(s) (floor={}), collected {} blob(s)",
                            reap.reaped, reap.floor, gc.deleted
                        );
                    }
                }
                Ok((Err(e), _)) | Ok((_, Err(e))) => eprintln!("amallo: store maintenance failed: {e}"),
                Err(e) => eprintln!("amallo: store maintenance task panicked: {e}"),
            }

            tokio::time::sleep(MAINTENANCE_INTERVAL).await;
        }
    });
}

/// `info`/`pull`/`push`/`blobs/check` - JSON bodies, capped at a document
/// size rather than a blob size. Split from `blob_routes` so the caller can
/// give each tier its own `DefaultBodyLimit`.
pub fn doc_routes() -> Router<ProxyCtx> {
    Router::new()
        .route("/extended/v1/info", get(info))
        .route("/extended/v1/pull", post(pull))
        .route("/extended/v1/push", post(push))
        .route("/extended/v1/blobs/check", post(blobs_check))
}

/// Raw-bytes upload/download - needs a much larger body limit than the doc
/// routes.
pub fn blob_routes() -> Router<ProxyCtx> {
    Router::new().route("/extended/v1/blob/{hash}", get(blob_get).put(blob_put))
}

// --- shared wire types -------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiError {
    error: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reap_floor: Option<i64>,
}

fn err(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: code,
            message: message.into(),
            reap_floor: None,
        }),
    )
        .into_response()
}

fn err_reap_floor(code: &'static str, message: impl Into<String>, reap_floor: i64) -> Response {
    (
        StatusCode::CONFLICT,
        Json(ApiError {
            error: code,
            message: message.into(),
            reap_floor: Some(reap_floor),
        }),
    )
        .into_response()
}

// --- GET /extended/v1/info ----------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    max_doc_bytes: u64,
    max_blob_bytes: u64,
    max_push_records: u32,
    max_pull_records: u32,
    max_blob_check_hashes: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NamespaceStatWire {
    namespace: String,
    live: i64,
    deleted: i64,
    max_seq: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoResponse {
    protocol: u32,
    store_id: String,
    head: i64,
    reap_floor: i64,
    server_time: i64,
    limits: Limits,
    namespaces: Vec<NamespaceStatWire>,
}

async fn info(State(ctx): State<ProxyCtx>) -> Response {
    let state = ctx.state.clone();
    let snapshot = match tokio::task::spawn_blocking(move || state.store.info()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    };

    Json(InfoResponse {
        protocol: PROTOCOL_VERSION,
        store_id: snapshot.store_id,
        head: snapshot.head,
        reap_floor: snapshot.reap_floor,
        server_time: now_ms(),
        limits: Limits {
            max_doc_bytes: MAX_DOC_BYTES,
            max_blob_bytes: MAX_BLOB_BYTES,
            max_push_records: MAX_PUSH_RECORDS as u32,
            max_pull_records: MAX_PULL_RECORDS,
            max_blob_check_hashes: MAX_BLOB_CHECK_HASHES as u32,
        },
        namespaces: snapshot
            .namespaces
            .into_iter()
            .map(|n| NamespaceStatWire {
                namespace: n.namespace,
                live: n.live,
                deleted: n.deleted,
                max_seq: n.max_seq,
            })
            .collect(),
    })
    .into_response()
}

// --- POST /extended/v1/pull ----------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyRefWire {
    namespace: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullRequestWire {
    #[serde(default)]
    since: i64,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    namespaces: Option<Vec<String>>,
    #[serde(default)]
    meta_only: bool,
    #[serde(default)]
    keys: Option<Vec<KeyRefWire>>,
    /// Device identity for tombstone-reaping's per-client cursor floor.
    /// Not a credential - just a UUID the client mints once.
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordWire<'a> {
    namespace: String,
    key: String,
    seq: i64,
    hash: String,
    updated_at: i64,
    deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a RawValue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PullResponse<'a> {
    store_id: String,
    head: i64,
    reap_floor: i64,
    cursor: i64,
    more: bool,
    records: Vec<RecordWire<'a>>,
}

async fn pull(State(ctx): State<ProxyCtx>, Json(req): Json<PullRequestWire>) -> Response {
    if let Some(ns) = &req.namespaces {
        for n in ns {
            if !validate::valid_namespace(n) {
                return err(StatusCode::BAD_REQUEST, "invalidNamespace", format!("invalid namespace: {n}"));
            }
        }
    }
    let keys = match &req.keys {
        Some(keys) => {
            let mut out = Vec::with_capacity(keys.len());
            for k in keys {
                if !validate::valid_namespace(&k.namespace) {
                    return err(StatusCode::BAD_REQUEST, "invalidNamespace", format!("invalid namespace: {}", k.namespace));
                }
                if !validate::valid_key(&k.key) {
                    return err(StatusCode::BAD_REQUEST, "invalidKey", format!("invalid key: {}", k.key));
                }
                out.push((k.namespace.clone(), k.key.clone()));
            }
            Some(out)
        }
        None => None,
    };

    let limit = req.limit.unwrap_or(DEFAULT_PULL_LIMIT).clamp(1, MAX_PULL_RECORDS);
    let query = PullQuery {
        since: req.since,
        limit,
        namespaces: req.namespaces.clone(),
        meta_only: req.meta_only,
        keys,
    };

    let state = ctx.state.clone();
    let outcome = match tokio::task::spawn_blocking(move || state.store.pull(query)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    };

    // A cursor below the reap floor may have missed tombstones the server
    // already collected - the client cannot trust an incremental pull from
    // there and must fall back to a full metaOnly reconcile.
    if req.since > 0 && req.since < outcome.reap_floor {
        return err_reap_floor(
            "cursorBelowReapFloor",
            "cursor is older than this store's tombstone retention window; full resync required",
            outcome.reap_floor,
        );
    }

    if let Some(client_id) = &req.client_id {
        if !client_id.is_empty() && client_id.len() <= 128 {
            let state = ctx.state.clone();
            let client_id = client_id.clone();
            let cursor = outcome.cursor;
            tokio::task::spawn_blocking(move || state.store.record_client_cursor(&client_id, cursor, now_ms()))
                .await
                .ok();
        }
    }

    // `RecordWire.data` borrows a `RawValue` so `Json`'s serializer writes
    // the stored JSON text verbatim into the response body. Going through
    // `serde_json::Value` instead (as an earlier version of this handler
    // did) would silently break byte-identical preservation: `Value`
    // reconstructs objects into a map with no guaranteed key order,
    // defeating the "hash is over exact bytes" design the whole client
    // integrity check depends on. These owned `Box<RawValue>`s just need to
    // outlive the `Json(..).into_response()` call below, which they do by
    // virtue of normal scope.
    let data_raws: Vec<Option<Box<RawValue>>> = outcome
        .records
        .iter()
        .map(|r| {
            r.data.as_deref().map(|s| {
                RawValue::from_string(s.to_string())
                    .unwrap_or_else(|_| RawValue::from_string("null".to_string()).unwrap())
            })
        })
        .collect();

    let records: Vec<RecordWire> = outcome
        .records
        .iter()
        .zip(data_raws.iter())
        .map(|(r, data_raw)| RecordWire {
            namespace: r.namespace.clone(),
            key: r.key.clone(),
            seq: r.seq,
            hash: r.hash.clone(),
            updated_at: r.updated_at,
            deleted: r.deleted,
            data: data_raw.as_deref(),
        })
        .collect();

    Json(PullResponse {
        store_id: outcome.store_id,
        head: outcome.head,
        reap_floor: outcome.reap_floor,
        cursor: outcome.cursor,
        more: outcome.more,
        records,
    })
    .into_response()
}

// --- POST /extended/v1/push -----------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRecordWire {
    namespace: String,
    key: String,
    hash: String,
    updated_at: i64,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    data: Option<Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRequestWire {
    #[serde(default)]
    records: Vec<PushRecordWire>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PushResultWire {
    namespace: String,
    key: String,
    status: &'static str,
    seq: i64,
    hash: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_blobs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PushResponse {
    store_id: String,
    head: i64,
    results: Vec<PushResultWire>,
}

fn push_status_str(s: PushStatus) -> &'static str {
    match s {
        PushStatus::Applied => "applied",
        PushStatus::Duplicate => "duplicate",
        PushStatus::Superseded => "superseded",
        PushStatus::MissingBlobs => "missingBlobs",
        PushStatus::Rejected => "rejected",
    }
}

async fn push(State(ctx): State<ProxyCtx>, Json(req): Json<PushRequestWire>) -> Response {
    if req.records.len() > MAX_PUSH_RECORDS {
        return err(
            StatusCode::BAD_REQUEST,
            "tooManyRecords",
            format!("push carries {} records, max is {MAX_PUSH_RECORDS}", req.records.len()),
        );
    }

    // Namespace/key/hash charset and per-doc size are checked here rather
    // than only inside `store::push`: an oversized or malformed record
    // should never even reach a SHA-256 pass or a write transaction.
    let mut records = Vec::with_capacity(req.records.len());
    let mut precomputed_rejections = Vec::new();
    for (i, rec) in req.records.into_iter().enumerate() {
        if !validate::valid_namespace(&rec.namespace) {
            precomputed_rejections.push((i, rec.namespace.clone(), rec.key.clone(), "invalid namespace".to_string()));
            continue;
        }
        if !validate::valid_key(&rec.key) {
            precomputed_rejections.push((i, rec.namespace.clone(), rec.key.clone(), "invalid key".to_string()));
            continue;
        }
        if !validate::valid_hash(&rec.hash) {
            precomputed_rejections.push((i, rec.namespace.clone(), rec.key.clone(), "invalid hash".to_string()));
            continue;
        }
        let data_text = rec.data.as_ref().map(|d| d.get().to_string());
        if let Some(text) = &data_text {
            if text.len() as u64 > MAX_DOC_BYTES {
                precomputed_rejections.push((i, rec.namespace.clone(), rec.key.clone(), "document too large".to_string()));
                continue;
            }
        }
        records.push((
            i,
            PushRecord {
                namespace: rec.namespace,
                key: rec.key,
                hash: rec.hash,
                updated_at: rec.updated_at,
                deleted: rec.deleted,
                data: data_text,
            },
        ));
    }

    let state = ctx.state.clone();
    let now = now_ms();
    let batch: Vec<PushRecord> = records.iter().map(|(_, r)| r.clone()).collect();
    let outcomes = match tokio::task::spawn_blocking(move || state.store.push(batch, now)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    };

    // Reassemble results in the original request order: `records` may have
    // skipped indices (pre-validated rejections), and `outcomes` is in the
    // order `records` was submitted in.
    let mut results: Vec<Option<PushResultWire>> =
        (0..records.len() + precomputed_rejections.len()).map(|_| None).collect();
    for ((orig_i, _), outcome) in records.iter().zip(outcomes.into_iter()) {
        results[*orig_i] = Some(PushResultWire {
            namespace: outcome.namespace,
            key: outcome.key,
            status: push_status_str(outcome.status),
            seq: outcome.seq,
            hash: outcome.hash,
            missing_blobs: outcome.missing_blobs,
            message: outcome.message,
        });
    }
    for (orig_i, namespace, key, message) in precomputed_rejections {
        results[orig_i] = Some(PushResultWire {
            namespace,
            key,
            status: "rejected",
            seq: 0,
            hash: String::new(),
            missing_blobs: Vec::new(),
            message: Some(message),
        });
    }

    let state = ctx.state.clone();
    let head = match tokio::task::spawn_blocking(move || state.store.info()).await {
        Ok(Ok(s)) => s.head,
        _ => 0,
    };

    Json(PushResponse {
        store_id: ctx.state.store.store_id.clone(),
        head,
        results: results.into_iter().map(|r| r.expect("every index filled")).collect(),
    })
    .into_response()
}

// --- POST /extended/v1/blobs/check ----------------------------------------

#[derive(Debug, Deserialize)]
struct BlobCheckRequest {
    #[serde(default)]
    hashes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BlobCheckResponse {
    missing: Vec<String>,
}

async fn blobs_check(State(ctx): State<ProxyCtx>, Json(req): Json<BlobCheckRequest>) -> Response {
    if req.hashes.len() > MAX_BLOB_CHECK_HASHES {
        return err(
            StatusCode::BAD_REQUEST,
            "tooManyRecords",
            format!("blobs/check carries {} hashes, max is {MAX_BLOB_CHECK_HASHES}", req.hashes.len()),
        );
    }
    // De-dupe defensively: a client sending the same hash twice shouldn't
    // cost two lookups, and the response should not repeat it either.
    let hashes: Vec<String> = req.hashes.into_iter().collect::<HashSet<_>>().into_iter().collect();

    let state = ctx.state.clone();
    let missing = match tokio::task::spawn_blocking(move || state.store.missing_blobs(&hashes)).await {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    };

    Json(BlobCheckResponse { missing }).into_response()
}

// --- PUT/GET /extended/v1/blob/{hash} -------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlobPutResponse {
    hash: String,
    size: u64,
    created: bool,
}

async fn blob_put(State(ctx): State<ProxyCtx>, AxumPath(hash): AxumPath<String>, body: Bytes) -> Response {
    if !validate::valid_hash(&hash) {
        return err(StatusCode::BAD_REQUEST, "invalidHash", "hash must be 64 lowercase hex digits");
    }
    let state = ctx.state.clone();
    let now = now_ms();
    let bytes = body.to_vec();
    let result = tokio::task::spawn_blocking(move || state.store.put_blob(&hash, &bytes, now)).await;

    match result {
        Ok(Ok(outcome)) => Json(BlobPutResponse {
            hash: outcome.hash,
            size: outcome.size,
            created: outcome.created,
        })
        .into_response(),
        Ok(Err(BlobError::InvalidHash)) => err(StatusCode::BAD_REQUEST, "invalidHash", "hash must be 64 lowercase hex digits"),
        Ok(Err(e @ BlobError::HashMismatch { .. })) => err(StatusCode::BAD_REQUEST, "hashMismatch", e.to_string()),
        Ok(Err(e @ BlobError::TooLarge { .. })) => err(StatusCode::PAYLOAD_TOO_LARGE, "blobTooLarge", e.to_string()),
        Ok(Err(BlobError::Io(msg))) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal", msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    }
}

async fn blob_get(State(ctx): State<ProxyCtx>, AxumPath(hash): AxumPath<String>) -> Response {
    if !validate::valid_hash(&hash) {
        return err(StatusCode::BAD_REQUEST, "invalidHash", "hash must be 64 lowercase hex digits");
    }
    let state = ctx.state.clone();
    let hash_for_read = hash.clone();
    let bytes = match tokio::task::spawn_blocking(move || state.store.read_blob(&hash_for_read)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string()),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("task failed: {e}")),
    };

    match bytes {
        Some(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::ETAG, format!("\"{hash}\"")),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable".to_string()),
            ],
            bytes,
        )
            .into_response(),
        None => err(StatusCode::NOT_FOUND, "notFound", "blob not found"),
    }
}
