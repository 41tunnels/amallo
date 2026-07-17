use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Manager, Wry};

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
struct ProxyCtx {
    state: Arc<AppState>,
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

fn router(state: Arc<AppState>) -> Router {
    let ctx = ProxyCtx {
        state,
        client: reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            // No overall timeout: generation streams can run for minutes.
            .build()
            .expect("reqwest client"),
    };
    Router::new()
        .fallback(forward)
        .layer(middleware::from_fn_with_state(ctx.clone(), require_bearer))
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

    let router = router(state.clone());
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
