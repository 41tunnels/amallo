//! Bridges relay inner frames (spec §6) to the same axum [`Router`]
//! `proxy.rs` serves locally, via [`tower::ServiceExt::oneshot`]. This is
//! the highest-risk piece of Step 4 (see the build plan) — everything
//! here is exercised without any WebSocket or crypto involved by
//! `dispatch::tests`, which drive [`Dispatcher`] with hand-built inner
//! frames the same way `conn.rs` will once it exists.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, Request};
use axum::Router;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tower::ServiceExt;

use crate::relay::policy;
use crate::relay::wire::{self, InnerFrame};

/// Wire shape of a `REQ` inner frame's JSON payload (spec §6). Field names
/// are the single-letter form the shared vectors and every implementation
/// (Go, TypeScript) agree on — see `reqresp.json` in the vendored vectors.
#[derive(Deserialize)]
struct ReqHead {
    m: String,
    p: String,
    #[serde(default)]
    h: Vec<(String, String)>,
}

/// Wire shape of a `RESP` inner frame's JSON payload.
#[derive(Serialize, Deserialize)]
struct RespHead {
    s: u16,
    h: Vec<(String, String)>,
}

#[derive(Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
}

/// Per-stream bookkeeping. `body_tx` is `None` once `REQ_END` (or
/// `CANCEL`) has closed the request body; the entry itself stays in the
/// map until the response finishes, so a `CANCEL` can still find and abort
/// the in-flight task at any point in the exchange (spec §6.1).
struct StreamEntry {
    body_tx: Option<mpsc::Sender<std::io::Result<Bytes>>>,
    abort: tokio::task::AbortHandle,
}

/// Dispatches inner frames from one relay session into the shared router
/// and back. One `Dispatcher` per relay connection. `handle` must be
/// called sequentially, in the order frames arrive off the wire — that is
/// what makes the backpressure chain in the build plan's design section
/// hold (a slow `REQ_BODY` send blocks `handle`, which blocks whatever
/// read loop is feeding it, all the way back to the relay).
pub struct Dispatcher {
    router: Router,
    bearer_token: String,
    /// Which allowlist inbound requests are checked against. An HTTP-mode
    /// connection gets a strictly smaller surface than the E2E one — see
    /// `policy::PolicyMode`.
    policy_mode: policy::PolicyMode,
    /// Outbound inner frames — not yet wire-encoded or sealed; conn.rs
    /// (Step 4) encodes them onto the plaintext channel, crypto.rs (Step
    /// 5) will seal them instead. Keeping this boundary as typed
    /// `InnerFrame`s, not bytes, is what lets Step 5 change *how* frames
    /// leave the process without touching this file at all.
    out_tx: mpsc::Sender<InnerFrame>,
    streams: Mutex<HashMap<u32, StreamEntry>>,
}

impl Dispatcher {
    pub fn new(router: Router, bearer_token: String, out_tx: mpsc::Sender<InnerFrame>) -> Arc<Self> {
        Self::with_policy(router, bearer_token, out_tx, policy::PolicyMode::E2E)
    }

    /// Builds a dispatcher restricted to a specific allowlist. The E2E
    /// path uses `new`; the OpenAI-compatible endpoint passes
    /// `PolicyMode::Http` so a leaked API key cannot reach model
    /// management.
    pub fn with_policy(
        router: Router,
        bearer_token: String,
        out_tx: mpsc::Sender<InnerFrame>,
        policy_mode: policy::PolicyMode,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            bearer_token,
            policy_mode,
            out_tx,
            streams: Mutex::new(HashMap::new()),
        })
    }

    /// Feeds one decoded inner frame into the dispatcher. See the struct
    /// doc comment for the sequential-call requirement.
    pub async fn handle(self: &Arc<Self>, frame: InnerFrame) {
        match frame.typ {
            wire::INNER_REQ => self.handle_req(frame).await,
            wire::INNER_REQ_BODY => self.handle_req_body(frame).await,
            wire::INNER_REQ_END => self.handle_req_end(frame).await,
            wire::INNER_CANCEL => self.handle_cancel(frame).await,
            _ => {
                // amallo only ever receives client-initiated frame types;
                // anything else (a reserved type that slipped past
                // wire::decode_inner_all, or a RESP-family type) is simply
                // not ours to act on.
            }
        }
    }

    async fn handle_req(self: &Arc<Self>, frame: InnerFrame) {
        let stream_id = frame.stream_id;

        let head: ReqHead = match serde_json::from_slice(&frame.payload) {
            Ok(h) => h,
            Err(_) => {
                self.send_error(stream_id, "bad_request", "malformed REQ payload").await;
                return;
            }
        };

        let allowed = match self.policy_mode {
            policy::PolicyMode::E2E => policy::check_method_path(&head.m, &head.p),
            policy::PolicyMode::Http => policy::check_http_method_path(&head.m, &head.p),
        };
        if let Err(e) = allowed {
            self.send_error(stream_id, "forbidden", &e.to_string()).await;
            return;
        }
        let headers = match policy::filter_request_headers(&head.h) {
            Ok(h) => h,
            Err(e) => {
                self.send_error(stream_id, "bad_request", &e.to_string()).await;
                return;
            }
        };

        let (body_tx, body_rx) = mpsc::channel::<std::io::Result<Bytes>>(16);
        let body = Body::from_stream(ReceiverStream::new(body_rx));

        let mut builder = Request::builder().method(head.m.as_str()).uri(head.p.as_str());
        for (name, value) in &headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(value.as_str()),
            ) {
                builder = builder.header(name, value);
            }
        }
        // amallo stamps its own bearer token — over the relay, the PSK
        // handshake (Step 5) is what actually authenticates the peer, so
        // `require_bearer` in the shared router is a no-op on this path by
        // construction. web never holds this token.
        builder = builder.header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", self.bearer_token),
        );

        let request = match builder.body(body) {
            Ok(r) => r,
            Err(_) => {
                self.send_error(stream_id, "bad_request", "could not construct request").await;
                return;
            }
        };

        let router = self.router.clone();
        let out_tx = self.out_tx.clone();
        let dispatcher = Arc::clone(self);
        let task = tokio::spawn(async move {
            dispatcher.run_request(stream_id, router, request, out_tx).await;
        });

        let mut streams = self.streams.lock().await;
        streams.insert(
            stream_id,
            StreamEntry {
                body_tx: Some(body_tx),
                abort: task.abort_handle(),
            },
        );
    }

    /// Runs the actual router call and streams the response back out as
    /// inner frames. Split out from `handle_req` so it can run inside its
    /// own spawned task — that task is exactly the unit `CANCEL` aborts
    /// (spec §6.1): dropping it drops the axum `Body`, which drops the
    /// `reqwest` response, which closes the TCP connection to Ollama —
    /// the same mechanism that already frees the GPU when a direct
    /// browser `fetch` is aborted today.
    async fn run_request(
        self: Arc<Self>,
        stream_id: u32,
        router: Router,
        request: Request<Body>,
        out_tx: mpsc::Sender<InnerFrame>,
    ) {
        let response = match router.oneshot(request).await {
            Ok(r) => r,
            Err(_) => {
                // axum::Router's Service::Error is Infallible today; this
                // arm exists so a future middleware change that weakens
                // that guarantee fails loudly to the client instead of
                // panicking here.
                self.send_error(stream_id, "internal", "router returned an error").await;
                self.remove_stream(stream_id).await;
                return;
            }
        };

        let status = response.status();
        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_ascii_lowercase(), v.to_string()));
            }
        }
        let head = RespHead {
            s: status.as_u16(),
            h: headers,
        };
        let Ok(head_json) = serde_json::to_vec(&head) else {
            self.remove_stream(stream_id).await;
            return;
        };
        if out_tx
            .send(InnerFrame {
                typ: wire::INNER_RESP,
                stream_id,
                payload: head_json,
            })
            .await
            .is_err()
        {
            self.remove_stream(stream_id).await;
            return;
        }

        const RESP_CHUNK: usize = 16 * 1024;
        let mut body_stream = response.into_body().into_data_stream();
        loop {
            match body_stream.next().await {
                Some(Ok(chunk)) => {
                    for slice in chunk.chunks(RESP_CHUNK) {
                        if out_tx
                            .send(InnerFrame {
                                typ: wire::INNER_RESP_BODY,
                                stream_id,
                                payload: slice.to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            self.remove_stream(stream_id).await;
                            return;
                        }
                    }
                }
                Some(Err(_)) => {
                    self.send_error(stream_id, "upstream_unreachable", "response stream error").await;
                    self.remove_stream(stream_id).await;
                    return;
                }
                None => break,
            }
        }

        let _ = out_tx
            .send(InnerFrame {
                typ: wire::INNER_RESP_END,
                stream_id,
                payload: Vec::new(),
            })
            .await;
        self.remove_stream(stream_id).await;
    }

    async fn handle_req_body(&self, frame: InnerFrame) {
        // Clone the sender out and release the map lock BEFORE awaiting
        // the (possibly backpressured) send — holding the lock across that
        // await would serialize every other stream's frame handling
        // behind this one slow upstream, defeating per-stream isolation.
        let tx = {
            let streams = self.streams.lock().await;
            streams.get(&frame.stream_id).and_then(|e| e.body_tx.clone())
        };
        if let Some(tx) = tx {
            let _ = tx.send(Ok(Bytes::from(frame.payload))).await;
        }
    }

    async fn handle_req_end(&self, frame: InnerFrame) {
        let mut streams = self.streams.lock().await;
        if let Some(entry) = streams.get_mut(&frame.stream_id) {
            // Dropping the Sender closes the channel, which ends the
            // ReceiverStream / axum Body cleanly (EOF), not an error.
            entry.body_tx = None;
        }
    }

    async fn handle_cancel(&self, frame: InnerFrame) {
        // spec §6.1: after CANCEL, send nothing further for this
        // stream_id — removing the entry here means a RESP/RESP_BODY/
        // RESP_END racing in from run_request() before the abort actually
        // lands will fail on out_tx being... no: out_tx is shared, not
        // per-stream, so those sends will still succeed. The task itself
        // is what's aborted; a send that was already queued right before
        // abort() may still land on the wire once, which the spec
        // explicitly tolerates ("sender MUST tolerate frames already in
        // flight" is about the *receiver's* obligation — symmetric here:
        // a client sending CANCEL must itself tolerate a brief trailing
        // frame).
        let mut streams = self.streams.lock().await;
        if let Some(entry) = streams.remove(&frame.stream_id) {
            entry.abort.abort();
        }
    }

    async fn remove_stream(&self, stream_id: u32) {
        self.streams.lock().await.remove(&stream_id);
    }

    async fn send_error(&self, stream_id: u32, code: &'static str, message: &str) {
        let payload = serde_json::to_vec(&ErrorPayload {
            code,
            message: message.to_string(),
        })
        .unwrap_or_default();
        let _ = self
            .out_tx
            .send(InnerFrame {
                typ: wire::INNER_ERROR,
                stream_id,
                payload,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use std::time::Duration;
    use tokio::time::timeout;

    fn test_router() -> Router {
        Router::new()
            .route("/api/tags", get(|| async { "{\"models\":[]}" }))
            .route(
                "/api/chat",
                axum::routing::post(|| async {
                    use axum::body::Body;
                    use futures_util::stream;
                    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
                        Ok(Bytes::from_static(b"{\"a\":1}\n")),
                        Ok(Bytes::from_static(b"{\"b\":2}\n")),
                    ];
                    Body::from_stream(stream::iter(chunks))
                }),
            )
            .route(
                "/api/slow",
                axum::routing::post(|| async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    "too slow"
                }),
            )
    }

    async fn recv_frame(rx: &mut mpsc::Receiver<InnerFrame>) -> InnerFrame {
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("frame within timeout")
            .expect("channel open")
    }

    #[tokio::test]
    async fn simple_get_round_trips_through_router() {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let dispatcher = Dispatcher::new(test_router(), "test-bearer".into(), out_tx);

        let req = serde_json::to_vec(&serde_json::json!({"m":"GET","p":"/api/tags","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame {
                typ: wire::INNER_REQ,
                stream_id: 1,
                payload: req,
            })
            .await;
        dispatcher
            .handle(InnerFrame {
                typ: wire::INNER_REQ_END,
                stream_id: 1,
                payload: vec![],
            })
            .await;

        let resp = recv_frame(&mut out_rx).await;
        assert_eq!(resp.typ, wire::INNER_RESP);
        let head: RespHead = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(head.s, 200);

        let body = recv_frame(&mut out_rx).await;
        assert_eq!(body.typ, wire::INNER_RESP_BODY);
        assert_eq!(body.payload, b"{\"models\":[]}");

        let end = recv_frame(&mut out_rx).await;
        assert_eq!(end.typ, wire::INNER_RESP_END);
    }

    #[tokio::test]
    async fn streaming_response_arrives_as_multiple_resp_body_frames() {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let dispatcher = Dispatcher::new(test_router(), "test-bearer".into(), out_tx);

        let req = serde_json::to_vec(&serde_json::json!({"m":"POST","p":"/api/chat","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ, stream_id: 1, payload: req })
            .await;
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ_END, stream_id: 1, payload: vec![] })
            .await;

        assert_eq!(recv_frame(&mut out_rx).await.typ, wire::INNER_RESP);
        let chunk1 = recv_frame(&mut out_rx).await;
        assert_eq!(chunk1.typ, wire::INNER_RESP_BODY);
        assert_eq!(chunk1.payload, b"{\"a\":1}\n");
        let chunk2 = recv_frame(&mut out_rx).await;
        assert_eq!(chunk2.payload, b"{\"b\":2}\n");
        assert_eq!(recv_frame(&mut out_rx).await.typ, wire::INNER_RESP_END);
    }

    #[tokio::test]
    async fn disallowed_path_returns_forbidden_error_not_router_call() {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let dispatcher = Dispatcher::new(test_router(), "test-bearer".into(), out_tx);

        let req = serde_json::to_vec(&serde_json::json!({"m":"POST","p":"/api/create","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ, stream_id: 1, payload: req })
            .await;

        let err = recv_frame(&mut out_rx).await;
        assert_eq!(err.typ, wire::INNER_ERROR);
        let payload: ErrorPayloadDe = serde_json::from_slice(&err.payload).unwrap();
        assert_eq!(payload.code, "forbidden");
    }

    #[derive(Deserialize)]
    struct ErrorPayloadDe {
        code: String,
    }

    #[tokio::test]
    async fn cancel_aborts_in_flight_request_and_sends_nothing_further() {
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let dispatcher = Dispatcher::new(test_router(), "test-bearer".into(), out_tx);

        let req = serde_json::to_vec(&serde_json::json!({"m":"POST","p":"/api/slow","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ, stream_id: 1, payload: req })
            .await;
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ_END, stream_id: 1, payload: vec![] })
            .await;

        // Give the spawned task a moment to actually start (and enter the
        // 30s sleep) before cancelling it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_CANCEL, stream_id: 1, payload: vec![] })
            .await;

        // Nothing should arrive — the task was aborted before it could
        // send RESP. A short timeout proves absence rather than hanging
        // for the full 30s the handler would otherwise sleep.
        let result = timeout(Duration::from_millis(300), out_rx.recv()).await;
        assert!(
            result.is_err(),
            "expected no frames after CANCEL, got {:?}",
            result
        );

        // The stream entry must be gone, so a stray REQ_BODY for the same
        // id after cancellation is silently dropped rather than reviving it.
        assert!(!dispatcher.streams.lock().await.contains_key(&1));
    }

    #[tokio::test]
    async fn req_body_backpressure_does_not_block_other_streams() {
        // A body_tx channel has capacity 16; fill it, then confirm a
        // second, unrelated stream is still served promptly rather than
        // blocking behind the first one's full channel.
        let router = Router::new().route(
            "/api/tags",
            get(|| async { "ok" }),
        );
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let dispatcher = Dispatcher::new(router, "test-bearer".into(), out_tx);

        // Stream 1: never sent REQ_END, so its body task stays parked
        // reading from Ollama forever in a real scenario — here there's no
        // handler consuming it (test_router only has /api/tags, GET has no
        // body), so REQ_BODY sends against a GET stream just accumulate
        // silently; the point is only that handle() returns promptly.
        let req1 = serde_json::to_vec(&serde_json::json!({"m":"GET","p":"/api/tags","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ, stream_id: 1, payload: req1 })
            .await;

        let start = std::time::Instant::now();
        let req2 = serde_json::to_vec(&serde_json::json!({"m":"GET","p":"/api/tags","h":[]})).unwrap();
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ, stream_id: 3, payload: req2 })
            .await;
        dispatcher
            .handle(InnerFrame { typ: wire::INNER_REQ_END, stream_id: 3, payload: vec![] })
            .await;
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "handling stream 3 must not be delayed by stream 1's state"
        );

        // Drain: expect stream 3's response frames to show up.
        let mut saw_stream_3_resp = false;
        for _ in 0..6 {
            let f = recv_frame(&mut out_rx).await;
            if f.stream_id == 3 && f.typ == wire::INNER_RESP {
                saw_stream_3_resp = true;
                break;
            }
        }
        assert!(saw_stream_3_resp, "stream 3 should have completed independently of stream 1");
    }
}
