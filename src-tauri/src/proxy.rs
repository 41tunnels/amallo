use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Manager, Wry};
use tower_http::cors::{Any, CorsLayer};

use crate::state::AppState;

pub(crate) const OLLAMA_UPSTREAM: &str = "http://127.0.0.1:11434";

/// Headers that must not be forwarded in either direction (hop-by-hop), plus
/// the ones Ollama trips over: `Host`/`Origin` make its allowed-host and CORS
/// middleware return 403, and `Authorization` is ours, not Ollama's.
const SKIP_REQUEST_HEADERS: &[HeaderName] = &[
    header::HOST,
    header::ORIGIN,
    header::AUTHORIZATION,
    header::CONNECTION,
    header::CONTENT_LENGTH,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::TE,
    header::TRAILER,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
];

const SKIP_RESPONSE_HEADERS: &[HeaderName] = &[
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::TE,
    header::TRAILER,
];

#[derive(Clone)]
pub(crate) struct ProxyCtx {
    pub(crate) state: Arc<AppState>,
    client: reqwest::Client,
}

/// Extract the bearer credential from an Authorization header value.
/// Accepts any casing of the `Bearer` scheme (RFC 7235 is case-insensitive).
fn bearer_credential(value: &str) -> Option<&str> {
    let value = value.trim();
    let (scheme, rest) = value.split_once(|c: char| c.is_whitespace())?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = rest.trim();
        (!token.is_empty()).then_some(token)
    } else {
        None
    }
}

/// Constant-time bearer token check. Every path requires auth so the public
/// surface stays dark.
async fn require_bearer(
    State(ctx): State<ProxyCtx>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let expected = ctx.state.bearer_token();
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let fail_reason = match auth_header {
        None => Some("missing Authorization header"),
        Some(raw) => match bearer_credential(raw) {
            None => Some("Authorization is not a Bearer token"),
            Some(token) if token.len() != expected.len() => {
                Some("bearer token length mismatch")
            }
            Some(token) if !bool::from(token.as_bytes().ct_eq(expected.as_bytes())) => {
                Some("bearer token mismatch")
            }
            Some(_) => None,
        },
    };

    if let Some(reason) = fail_reason {
        eprintln!("amallo: auth failed {method} {path} — {reason}");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized\n",
        )
            .into_response();
    }

    next.run(req).await
}

fn copy_headers(src: &HeaderMap, skip: &[HeaderName]) -> HeaderMap {
    let mut dst = HeaderMap::new();
    for (name, value) in src {
        if !skip.contains(name) {
            dst.append(name.clone(), value.clone());
        }
    }
    dst
}

/// Catch-all handler: forward any method/path to Ollama, streaming both the
/// request and response bodies (NDJSON / SSE chunks must arrive incrementally).
async fn forward(State(ctx): State<ProxyCtx>, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let url = format!("{OLLAMA_UPSTREAM}{path_and_query}");

    let method = req.method().clone();
    let headers = copy_headers(req.headers(), SKIP_REQUEST_HEADERS);
    let body_stream = req.into_body().into_data_stream();

    let upstream = ctx
        .client
        .request(method.clone(), &url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body_stream))
        .send()
        .await;

    let upstream = match upstream {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("amallo: upstream failed {method} {path_and_query} — {e}");
            let msg = format!("amallo: could not reach Ollama at {OLLAMA_UPSTREAM}: {e}\n");
            return (StatusCode::BAD_GATEWAY, msg).into_response();
        }
    };

    let status = upstream.status();
    if !status.is_success() {
        eprintln!(
            "amallo: upstream {status} {method} {path_and_query} (from {OLLAMA_UPSTREAM})"
        );
    }

    let mut response_headers = copy_headers(upstream.headers(), SKIP_RESPONSE_HEADERS);
    response_headers.insert(
        HeaderName::from_static("x-proxied-by"),
        HeaderValue::from_static("amallo"),
    );

    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    *response.headers_mut() = response_headers;
    response
}

/// Builds the shared router — bearer auth, CORS, sync routes, and the
/// catch-all Ollama forward. Called once and cached in
/// `AppState.router` (see `respawn` below and `relay::respawn`): both the
/// local proxy listener and the relay dispatcher serve requests through
/// this exact router, so relay-originated requests get bearer auth (via
/// amallo's own stamped token — see `relay::dispatch`), CORS, and Ollama
/// forwarding for free, identically to a direct LAN connection.
pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    let ctx = ProxyCtx {
        state,
        client: reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            // No overall timeout: generation streams can run for minutes.
            .build()
            .expect("reqwest client"),
    };
    // Browser clients (e.g. OpenCharUI web) need CORS: preflights carry no
    // Authorization header, so this layer must sit outside the auth layer to
    // answer them, and to stamp Access-Control-Allow-Origin onto 401s so the
    // browser can read the status. Wildcard origin is fine — auth is a bearer
    // token, never cookies. `allow_headers` is explicit because the `*`
    // wildcard does not cover `Authorization` per the Fetch spec.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // amallo-native document sync (legacy). Explicit routes take precedence
    // over the catch-all `forward`, and `/amallo/*` cannot collide with
    // Ollama's `/api/*` or `/v1/*`. The larger body limit (avatar batches)
    // applies to this route only; the streaming fallback keeps axum's
    // default. Kept alive alongside `/extended/v1/*` until a later release
    // removes it once web has shipped against the new surface - see
    // `store::retire_legacy_sync_dir`.
    let sync_routes = Router::new()
        .route(
            "/amallo/sync/{collection}",
            get(crate::sync::sync_get).post(crate::sync::sync_post),
        )
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    // The generic document + blob store. Split into two body-limit tiers:
    // documents are capped much smaller than the old blanket 64 MiB (they
    // no longer carry inlined avatars - those go through the blob route,
    // which gets its own larger cap for the bytes themselves).
    let v1_doc_routes = crate::api::v1::doc_routes().layer(DefaultBodyLimit::max(8 * 1024 * 1024));
    let v1_blob_routes = crate::api::v1::blob_routes().layer(DefaultBodyLimit::max(33 * 1024 * 1024));

    Router::new()
        .merge(sync_routes)
        .merge(v1_doc_routes)
        .merge(v1_blob_routes)
        .fallback(forward)
        .layer(middleware::from_fn_with_state(ctx.clone(), require_bearer))
        .layer(cors) // added last => outermost, runs before auth
        .with_state(ctx)
}

/// (Re)start the proxy server according to the current settings. Aborts a
/// previously running listener first, so port/bind changes apply immediately.
pub fn respawn(app: &AppHandle<Wry>) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let settings = state.settings();

    let ip = if settings.bind_lan {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    let addr = SocketAddr::new(ip, settings.proxy_port);

    if let Some(task) = state.proxy_task.lock().unwrap().take() {
        task.abort();
    }

    let router = state
        .router
        .get_or_init(|| build_router(state.clone()))
        .clone();
    let task = tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("amallo: failed to bind proxy on {addr}: {e}");
                return;
            }
        };
        println!("amallo: proxy listening on http://{addr} -> {OLLAMA_UPSTREAM}");
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("amallo: proxy server error: {e}");
        }
    });

    *state.proxy_task.lock().unwrap() = Some(task);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    const TOKEN: &str = "test-token";

    /// Serve the real router on an ephemeral port. Returns the base URL and the
    /// sync-store temp dir guard, which the caller must keep alive for the test.
    async fn spawn_test_proxy() -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(
            AppState::new(TOKEN.to_string(), Settings::default(), dir.path().to_path_buf())
                .unwrap(),
        );
        let router = build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), dir)
    }

    #[tokio::test]
    async fn cors_preflight_passes_without_auth() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = reqwest::Client::new()
            .request(reqwest::Method::OPTIONS, format!("{base}/api/tags"))
            .header("Origin", "http://localhost:5173")
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
            .await
            .unwrap();

        assert!(res.status().is_success(), "preflight must not require auth");
        assert_eq!(
            res.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        let allow_headers = res
            .headers()
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(allow_headers.contains("authorization"));
    }

    #[tokio::test]
    async fn unauthorized_response_carries_cors_header() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = reqwest::Client::new()
            .get(format!("{base}/api/tags"))
            .header("Origin", "http://localhost:5173")
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[tokio::test]
    async fn bearer_token_still_required_for_actual_requests() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        let wrong = client
            .get(format!("{base}/api/tags"))
            .header("Authorization", "Bearer wrong-token")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);

        // With the right token auth passes; the request then reaches the
        // forwarder (200 if a local Ollama is running, 502 otherwise).
        let ok = client
            .get(format!("{base}/api/tags"))
            .header("Authorization", format!("Bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_ne!(ok.status(), reqwest::StatusCode::UNAUTHORIZED);

        // RFC 7235: auth scheme is case-insensitive.
        let lower = client
            .get(format!("{base}/api/tags"))
            .header("Authorization", format!("bearer {TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_ne!(lower.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn bearer_credential_parses_scheme_case_insensitively() {
        assert_eq!(bearer_credential("Bearer abc"), Some("abc"));
        assert_eq!(bearer_credential("bearer abc"), Some("abc"));
        assert_eq!(bearer_credential("BEARER  abc  "), Some("abc"));
        assert_eq!(bearer_credential("Basic abc"), None);
        assert_eq!(bearer_credential("Bearer"), None);
        assert_eq!(bearer_credential(""), None);
    }

    fn auth(client: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        client.header("Authorization", format!("Bearer {TOKEN}"))
    }

    #[tokio::test]
    async fn sync_round_trip_and_known_filtering() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        // Push two records.
        let resp = auth(client.post(format!("{base}/amallo/sync/characters")))
            .json(&serde_json::json!({
                "records": [
                    { "id": "a", "updatedAt": 100, "deleted": false, "data": { "name": "A" } },
                    { "id": "b", "updatedAt": 100, "deleted": false, "data": { "name": "B" } }
                ],
                "known": {}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        // A second client that knows a@100 but not b gets only b back.
        let body: serde_json::Value = auth(client.post(format!("{base}/amallo/sync/characters")))
            .json(&serde_json::json!({ "records": [], "known": { "a": 100 } }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let records = body["records"].as_array().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["id"], "b");

        // GET returns everything.
        let all: serde_json::Value = auth(client.get(format!("{base}/amallo/sync/characters")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(all["records"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn sync_tombstone_beats_data_then_resurrects() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        auth(client.post(format!("{base}/amallo/sync/chats")))
            .json(&serde_json::json!({
                "records": [{ "id": "c", "updatedAt": 100, "deleted": false, "data": { "t": "hi" } }],
                "known": {}
            }))
            .send()
            .await
            .unwrap();

        // Tombstone at the same timestamp wins the tie.
        auth(client.post(format!("{base}/amallo/sync/chats")))
            .json(&serde_json::json!({
                "records": [{ "id": "c", "updatedAt": 100, "deleted": true }],
                "known": {}
            }))
            .send()
            .await
            .unwrap();
        let all: serde_json::Value = auth(client.get(format!("{base}/amallo/sync/chats")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(all["records"][0]["deleted"], true);

        // A newer live record resurrects it.
        auth(client.post(format!("{base}/amallo/sync/chats")))
            .json(&serde_json::json!({
                "records": [{ "id": "c", "updatedAt": 200, "deleted": false, "data": { "t": "back" } }],
                "known": {}
            }))
            .send()
            .await
            .unwrap();
        let all: serde_json::Value = auth(client.get(format!("{base}/amallo/sync/chats")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(all["records"][0]["deleted"], false);
        assert_eq!(all["records"][0]["updatedAt"], 200);
    }

    #[tokio::test]
    async fn sync_reports_missing_for_wiped_server() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();
        let body: serde_json::Value = auth(client.post(format!("{base}/amallo/sync/personas")))
            .json(&serde_json::json!({ "records": [], "known": { "x": 100 } }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["missing"].as_array().unwrap(), &vec!["x"]);
    }

    #[tokio::test]
    async fn sync_requires_auth() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = reqwest::Client::new()
            .post(format!("{base}/amallo/sync/characters"))
            .json(&serde_json::json!({ "records": [], "known": {} }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sync_unknown_collection_is_404() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = auth(reqwest::Client::new().post(format!("{base}/amallo/sync/bogus")))
            .json(&serde_json::json!({ "records": [], "known": {} }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn sync_bad_json_is_rejected() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = auth(reqwest::Client::new().post(format!("{base}/amallo/sync/characters")))
            .header("Content-Type", "application/json")
            .body("not json")
            .send()
            .await
            .unwrap();
        assert!(res.status().is_client_error());
    }

    // --- /extended/v1/* -----------------------------------------------

    fn doc_hash(text: &str) -> String {
        crate::store::hash::sha256_hex(text.as_bytes())
    }

    fn push_record(namespace: &str, key: &str, data: &str, updated_at: i64) -> serde_json::Value {
        serde_json::json!({
            "namespace": namespace,
            "key": key,
            "hash": doc_hash(data),
            "updatedAt": updated_at,
            "deleted": false,
            "data": serde_json::from_str::<serde_json::Value>(data).unwrap()
        })
    }

    fn tombstone_record(namespace: &str, key: &str, updated_at: i64) -> serde_json::Value {
        serde_json::json!({
            "namespace": namespace,
            "key": key,
            "hash": crate::store::hash::EMPTY_HASH,
            "updatedAt": updated_at,
            "deleted": true
        })
    }

    #[tokio::test]
    async fn v1_push_then_pull_round_trip() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        let resp = auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({
                "records": [
                    push_record("characters", "a", r#"{"name":"A"}"#, 100),
                    push_record("characters", "b", r#"{"name":"B"}"#, 100)
                ]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "applied");
        assert_eq!(body["results"][1]["status"], "applied");

        let pulled: serde_json::Value = auth(client.post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": 0, "limit": 10 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let records = pulled["records"].as_array().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["data"]["name"], "A");
        assert!(!pulled["more"].as_bool().unwrap());

        // Paging by cursor: page1 excludes what page2 returns.
        let page1: serde_json::Value = auth(client.post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": 0, "limit": 1 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page1["records"].as_array().unwrap().len(), 1);
        assert!(page1["more"].as_bool().unwrap());
        let cursor = page1["cursor"].as_i64().unwrap();

        let page2: serde_json::Value = auth(client.post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": cursor, "limit": 1 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page2["records"].as_array().unwrap().len(), 1);
        assert!(!page2["more"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn v1_tombstone_beats_data_then_resurrects() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("chats", "c", r#"{"t":"hi"}"#, 100)] }))
            .send()
            .await
            .unwrap();

        // Tombstone at the same timestamp wins the tie.
        auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [tombstone_record("chats", "c", 100)] }))
            .send()
            .await
            .unwrap();

        let pulled: serde_json::Value = auth(client.post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": 0, "limit": 10 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(pulled["records"][0]["deleted"], true);

        // A newer live record resurrects it.
        auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("chats", "c", r#"{"t":"back"}"#, 200)] }))
            .send()
            .await
            .unwrap();

        let pulled: serde_json::Value = auth(client.post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": 0, "limit": 10 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(pulled["records"][0]["deleted"], false);
        assert_eq!(pulled["records"][0]["data"]["t"], "back");
    }

    #[tokio::test]
    async fn v1_requires_auth() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        for (method, path) in [
            (reqwest::Method::GET, "/extended/v1/info"),
            (reqwest::Method::POST, "/extended/v1/pull"),
            (reqwest::Method::POST, "/extended/v1/push"),
            (reqwest::Method::POST, "/extended/v1/blobs/check"),
            (reqwest::Method::PUT, "/extended/v1/blob/aa"),
            (reqwest::Method::GET, "/extended/v1/blob/aa"),
        ] {
            let res = client
                .request(method.clone(), format!("{base}{path}"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED, "{method} {path} must require auth");
        }
    }

    #[tokio::test]
    async fn v1_invalid_namespace_is_400_not_404() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        let res = auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("Bogus Namespace", "a", "{}", 1)] }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK, "push itself succeeds; the record is rejected");
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "rejected");
    }

    #[tokio::test]
    async fn v1_unknown_valid_namespace_pull_is_empty_200() {
        let (base, _dir) = spawn_test_proxy().await;
        let res = auth(reqwest::Client::new().post(format!("{base}/extended/v1/pull")))
            .json(&serde_json::json!({ "since": 0, "limit": 10, "namespaces": ["lorebooks"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK, "an unknown but well-formed namespace is not an error");
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(body["records"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn v1_push_hash_mismatch_is_rejected() {
        let (base, _dir) = spawn_test_proxy().await;
        let mut rec = push_record("characters", "a", r#"{"name":"A"}"#, 100);
        rec["hash"] = serde_json::Value::String(doc_hash("something else"));

        let res = auth(reqwest::Client::new().post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [rec] }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "rejected");
    }

    #[tokio::test]
    async fn v1_blob_round_trip_and_dedup_on_unrelated_edit() {
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();
        let bytes = b"pretend-avatar-bytes";
        let hash = crate::store::hash::sha256_hex(bytes);

        // Not yet uploaded: push referencing it comes back missingBlobs.
        let doc = format!(r#"{{"avatar":{{"$blob":"{hash}","mime":"image/png","size":21}}}}"#);
        let res = auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("characters", "a", &doc, 100)] }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "missingBlobs");
        assert_eq!(body["results"][0]["missingBlobs"][0], hash);

        // Check confirms it, upload it, check confirms it's gone.
        let check: serde_json::Value = auth(client.post(format!("{base}/extended/v1/blobs/check")))
            .json(&serde_json::json!({ "hashes": [hash] }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(check["missing"][0], hash);

        let put = auth(client.put(format!("{base}/extended/v1/blob/{hash}")))
            .body(bytes.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), reqwest::StatusCode::OK);

        let check: serde_json::Value = auth(client.post(format!("{base}/extended/v1/blobs/check")))
            .json(&serde_json::json!({ "hashes": [hash] }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(check["missing"].as_array().unwrap().is_empty());

        // Now the push applies, and the blob downloads byte-identically.
        let res = auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("characters", "a", &doc, 100)] }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "applied");

        let downloaded = auth(client.get(format!("{base}/extended/v1/blob/{hash}")))
            .send()
            .await
            .unwrap();
        assert_eq!(downloaded.status(), reqwest::StatusCode::OK);
        assert_eq!(downloaded.bytes().await.unwrap().as_ref(), bytes);

        // An edit to an unrelated field must not require re-uploading the
        // blob: the push carries the same $blob ref, already satisfied.
        let doc2 = format!(r#"{{"avatar":{{"$blob":"{hash}","mime":"image/png","size":21}},"name":"Ada"}}"#);
        let res = auth(client.post(format!("{base}/extended/v1/push")))
            .json(&serde_json::json!({ "records": [push_record("characters", "a", &doc2, 200)] }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["results"][0]["status"], "applied", "no missingBlobs the second time - it's already stored");
    }

    #[tokio::test]
    async fn v1_blob_hash_mismatch_is_rejected() {
        let (base, _dir) = spawn_test_proxy().await;
        let real_hash = crate::store::hash::sha256_hex(b"real bytes");
        let res = auth(reqwest::Client::new().put(format!("{base}/extended/v1/blob/{real_hash}")))
            .body("different bytes".to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn v1_blob_not_found_is_404() {
        let (base, _dir) = spawn_test_proxy().await;
        let absent = crate::store::hash::sha256_hex(b"never uploaded");
        let res = auth(reqwest::Client::new().get(format!("{base}/extended/v1/blob/{absent}")))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn v1_fresh_stores_have_distinct_store_ids() {
        let (base_a, _dir_a) = spawn_test_proxy().await;
        let (base_b, _dir_b) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        let info_a: serde_json::Value = auth(client.get(format!("{base_a}/extended/v1/info")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let info_b: serde_json::Value = auth(client.get(format!("{base_b}/extended/v1/info")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_ne!(info_a["storeId"], info_b["storeId"]);
        assert_eq!(info_a["protocol"], 1);
    }

    #[tokio::test]
    async fn v1_and_legacy_sync_coexist() {
        // The whole point of the coexistence release: both surfaces must
        // work side by side against the same running instance.
        let (base, _dir) = spawn_test_proxy().await;
        let client = reqwest::Client::new();

        let legacy = auth(client.post(format!("{base}/amallo/sync/characters")))
            .json(&serde_json::json!({ "records": [], "known": {} }))
            .send()
            .await
            .unwrap();
        assert_eq!(legacy.status(), reqwest::StatusCode::OK);

        let v1 = auth(client.get(format!("{base}/extended/v1/info")))
            .send()
            .await
            .unwrap();
        assert_eq!(v1.status(), reqwest::StatusCode::OK);
    }
}
