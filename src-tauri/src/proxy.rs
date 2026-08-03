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

const OLLAMA_UPSTREAM: &str = "http://127.0.0.1:11434";

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

/// Constant-time bearer token check. Every path requires auth so the public
/// surface stays dark.
async fn require_bearer(
    State(ctx): State<ProxyCtx>,
    req: Request,
    next: Next,
) -> Response {
    let expected = ctx.state.bearer_token();
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let ok = match provided {
        Some(token) => {
            token.len() == expected.len()
                && token.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        None => false,
    };

    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized\n",
        )
            .into_response()
    }
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
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{OLLAMA_UPSTREAM}{path_and_query}");

    let method = req.method().clone();
    let headers = copy_headers(req.headers(), SKIP_REQUEST_HEADERS);
    let body_stream = req.into_body().into_data_stream();

    let upstream = ctx
        .client
        .request(method, &url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body_stream))
        .send()
        .await;

    let upstream = match upstream {
        Ok(resp) => resp,
        Err(e) => {
            let msg = format!("amallo: could not reach Ollama at {OLLAMA_UPSTREAM}: {e}\n");
            return (StatusCode::BAD_GATEWAY, msg).into_response();
        }
    };

    let status = upstream.status();
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

    // amallo-native document sync. Explicit routes take precedence over the
    // catch-all `forward`, and `/amallo/*` cannot collide with Ollama's `/api/*`
    // or `/v1/*`. The larger body limit (avatar batches) applies to this route
    // only; the streaming fallback keeps axum's default.
    let sync_routes = Router::new()
        .route(
            "/amallo/sync/{collection}",
            get(crate::sync::sync_get).post(crate::sync::sync_post),
        )
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024));

    Router::new()
        .merge(sync_routes)
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
        let state = Arc::new(AppState::new(
            TOKEN.to_string(),
            Settings::default(),
            dir.path().to_path_buf(),
        ));
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
}
