//! The relay WebSocket connection itself: connect, hello, the E2E
//! handshake (spec §4), and the pump that decrypts incoming ciphertext
//! frames into a [`Dispatcher`] and encrypts outbound ones back onto the
//! wire (spec §5/§6). `run_once` is the real, production path; alongside
//! it, `run_once_insecure` is Step 4's plaintext dev bridge — channel
//! 0x01 carries raw wire-encoded bytes with no AEAD wrapping at all, only
//! reachable via `AMALLO_RELAY_INSECURE=1`, and MUST NEVER be used
//! against a production relay.

use std::sync::Arc;

use axum::Router;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::Deserialize;
use tauri::{AppHandle, Wry};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::relay::crypto;
use crate::relay::dispatch::Dispatcher;
use crate::relay::set_status;
use crate::relay::wire::{self, InnerFrame};
use crate::state::RelayStatus;

/// Bound on the outbound-frame channel between the Dispatcher (and its
/// per-request response-streaming tasks) and the single writer task that
/// owns the WebSocket sink and, in the real path, the [`crypto::Sealer`]
/// — spec §5.1's "exactly one sealing point per direction" rule, enforced
/// structurally: nothing but the writer task ever calls `seal`.
const OUT_CHANNEL_CAPACITY: usize = 64;

/// The outer-frame header every ciphertext frame in this codebase is sent
/// under: channel 0x01, no flags (v1 has no `conn_id`). Constant because
/// it never varies — see spec §5's AAD definition.
const CIPHERTEXT_HEADER: [u8; 2] = [wire::CHANNEL_CIPHERTEXT.0, 0];

#[derive(Deserialize)]
struct ControlMsg {
    t: String,
    #[serde(default)]
    code: String,
}

// --- real (encrypted) path ---------------------------------------------

/// Runs one connection attempt to completion: dial, hello, wait for a web
/// peer, perform the E2E handshake, then pump encrypted frames until the
/// connection ends for any reason. Returns `Ok(())` for an ordinary end
/// (peer disconnected, relay went away) and `Err` describing a real
/// failure; either way the caller (`relay::supervise`) owns backoff and
/// reconnection — this function never retries on its own.
///
/// Simplification worth knowing: this performs exactly one handshake per
/// connection attempt. If the attached web client disconnects and a
/// different one attaches to the same pair, this function returns (the
/// stale `Sealer`/`Opener` can't safely serve a different peer's session)
/// and the supervisor's next attempt starts fresh — one extra reconnect
/// round-trip on client rotation, not a partial/incorrect session. The
/// same limitation exists in the relay repo's own `fakeagent` reference
/// tool.
pub async fn run_once(
    app: &AppHandle<Wry>,
    relay_url: &str,
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: Router,
    bearer_token: String,
) -> Result<(), String> {
    run_once_with_status(relay_url, pair_id, psk, router, bearer_token, |status| {
        set_status(app, status)
    })
    .await
}

/// The actual connection/handshake/pump logic, with no Tauri dependency
/// at all — `on_status` is called at each status transition instead of
/// this function reaching into an `AppHandle` itself. `run_once` is a
/// thin wrapper over this for the real supervisor; this split is what
/// lets the connection logic run and be verified (e.g. against a real
/// deployed relay, from a plain `main()`) without standing up a full
/// Tauri app.
pub async fn run_once_with_status(
    relay_url: &str,
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: Router,
    bearer_token: String,
    on_status: impl Fn(RelayStatus),
) -> Result<(), String> {
    let url = format!("{}/v1/agent", relay_url.trim_end_matches('/'));
    let (ws_stream, _) = connect_async(&url)
        .await
        .map_err(|e| format!("connect to {url}: {e}"))?;
    let (mut write, mut read) = ws_stream.split();

    send_hello(&mut write, pair_id).await?;
    expect_control(&mut read, "hello_ok").await?;

    on_status(RelayStatus::Waiting);
    match expect_control_or_going_away(&mut read, "peer_online").await? {
        ControlOutcome::Matched => {}
        ControlOutcome::GoingAway => return Ok(()),
    }

    on_status(RelayStatus::Connecting);
    let session = perform_handshake(&mut write, &mut read, pair_id, psk).await?;

    let sealer = crypto::Sealer::new(&session.k_a2w, &session.np_a2w)
        .map_err(|e| format!("build sealer: {}", crypto::error_code(e)))?;
    let opener = crypto::Opener::new(&session.k_w2a, &session.np_w2a)
        .map_err(|e| format!("build opener: {}", crypto::error_code(e)))?;

    let (out_tx, out_rx) = mpsc::channel::<InnerFrame>(OUT_CHANNEL_CAPACITY);
    let dispatcher = Dispatcher::new(router, bearer_token, out_tx);

    let writer_task = tokio::spawn(run_writer_secure(write, out_rx, sealer));

    on_status(RelayStatus::Online);
    let result = run_reader_secure(&mut read, &dispatcher, opener).await;

    writer_task.abort();
    result
}

struct HandshakeResult {
    k_a2w: Vec<u8>,
    k_w2a: Vec<u8>,
    np_a2w: Vec<u8>,
    np_w2a: Vec<u8>,
}

/// Performs spec §4's HELLO/CONFIRM exchange as the agent role: build and
/// send our HELLO, receive and verify the web peer's, derive the session
/// from the transcript + ECDH + PSK, then exchange and verify CONFIRM.
/// No channel-0x01 frame may be sent or accepted before this returns
/// successfully.
async fn perform_handshake<W, R>(
    write: &mut W,
    read: &mut R,
    pair_id: [u8; 16],
    psk: [u8; 32],
) -> Result<HandshakeResult, String>
where
    W: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    R: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let agent_eph = crypto::Ephemeral::generate().map_err(|e| format!("generate ephemeral: {}", crypto::error_code(e)))?;
    let mut agent_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut agent_nonce);

    let hello_agent = crypto::build_hello(&psk, crypto::ROLE_AGENT, pair_id, agent_eph.public_key_bytes(), agent_nonce)
        .map_err(|e| format!("build hello: {}", crypto::error_code(e)))?;
    send_handshake(write, &hello_agent).await?;

    let hello_web = expect_handshake(read).await?;
    let web_fields = crypto::verify_hello(&psk, &hello_web, pair_id, crypto::ROLE_AGENT)
        .map_err(|e| format!("verify peer hello: {}", crypto::error_code(e)))?;

    let transcript = crypto::transcript(&hello_agent, &hello_web);
    let ecdh_x = agent_eph
        .ecdh(&web_fields.epk)
        .map_err(|e| format!("ecdh: {}", crypto::error_code(e)))?;
    let session = crypto::derive_session(&psk, &transcript, &ecdh_x)
        .map_err(|e| format!("derive session: {}", crypto::error_code(e)))?;

    let confirm_agent = crypto::build_confirm(&session, crypto::ROLE_AGENT)
        .map_err(|e| format!("build confirm: {}", crypto::error_code(e)))?;
    send_handshake(write, &confirm_agent).await?;

    let confirm_web = expect_handshake(read).await?;
    crypto::verify_confirm(&session, &confirm_web, crypto::ROLE_CLIENT)
        .map_err(|e| format!("verify peer confirm: {}", crypto::error_code(e)))?;

    Ok(HandshakeResult {
        k_a2w: session.k_a2w,
        k_w2a: session.k_w2a,
        np_a2w: session.np_a2w,
        np_w2a: session.np_w2a,
    })
}

async fn send_handshake<S>(write: &mut S, payload: &[u8]) -> Result<(), String>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let frame = wire::encode_outer(wire::CHANNEL_HANDSHAKE, payload);
    write
        .send(Message::Binary(frame.into()))
        .await
        .map_err(|e| format!("send handshake frame: {e}"))
}

/// Reads exactly one message and returns its handshake-channel payload —
/// used only during `perform_handshake`, where no other frame type is
/// expected.
async fn expect_handshake<S>(read: &mut S) -> Result<Vec<u8>, String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = read
        .next()
        .await
        .ok_or_else(|| "connection closed during handshake".to_string())?
        .map_err(|e| format!("read handshake frame: {e}"))?;
    let Message::Binary(data) = msg else {
        return Err("expected a binary message for a handshake frame".to_string());
    };
    let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;
    if hdr.channel != wire::CHANNEL_HANDSHAKE {
        return Err(format!(
            "expected handshake channel during handshake, got 0x{:02x}",
            hdr.channel.0
        ));
    }
    Ok(payload.to_vec())
}

enum ControlOutcome {
    Matched,
    GoingAway,
}

/// Like `expect_control`, but treats an early `going_away` as a
/// non-fatal outcome the caller can react to (return cleanly and let the
/// supervisor reconnect) rather than a protocol error — the relay is
/// allowed to send this before a peer ever attaches.
async fn expect_control_or_going_away<S>(read: &mut S, want_type: &str) -> Result<ControlOutcome, String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let msg = read
            .next()
            .await
            .ok_or_else(|| format!("connection closed before {want_type}"))?
            .map_err(|e| format!("read {want_type}: {e}"))?;
        let Message::Binary(data) = msg else {
            return Err(format!("expected a binary message for {want_type}"));
        };
        let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;
        if hdr.channel != wire::CHANNEL_CONTROL {
            return Err(format!(
                "expected control channel for {want_type}, got 0x{:02x}",
                hdr.channel.0
            ));
        }
        let msg: ControlMsg = serde_json::from_slice(payload).map_err(|e| e.to_string())?;
        if msg.t == want_type {
            return Ok(ControlOutcome::Matched);
        }
        if msg.t == "going_away" {
            return Ok(ControlOutcome::GoingAway);
        }
        // Any other control message while waiting is unexpected but not
        // fatal on its own — keep waiting for the one we actually need.
    }
}

/// Owns the WebSocket sink and the [`crypto::Sealer`] exclusively — the
/// single writer/sealing point for this connection (spec §5.1). Every
/// outbound `InnerFrame` is wire-encoded, sealed, wrapped in a
/// channel-0x01 outer frame, and written in order.
async fn run_writer_secure<S>(mut write: S, mut out_rx: mpsc::Receiver<InnerFrame>, mut sealer: crypto::Sealer)
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    while let Some(frame) = out_rx.recv().await {
        let mut buf = Vec::new();
        if wire::encode_inner(&mut buf, &frame).is_err() {
            // Only a reserved-type or oversize-payload frame hits this,
            // neither of which dispatch.rs ever constructs — drop rather
            // than crash the writer over one bad outbound frame.
            continue;
        }
        let sealed = match sealer.seal(&CIPHERTEXT_HEADER, &buf) {
            Ok(s) => s,
            // Counter exhaustion (2^64 frames — never happens in
            // practice) or an internal AEAD failure: either way this
            // session can no longer seal safely. Tear the connection
            // down so the supervisor reconnects with a fresh session
            // rather than silently dropping frames forever.
            Err(_) => return,
        };
        let outer = wire::encode_outer(wire::CHANNEL_CIPHERTEXT, &sealed);
        if write.send(Message::Binary(outer.into())).await.is_err() {
            return;
        }
    }
}

/// Reads incoming messages until the connection ends, opening channel
/// 0x01 payloads with the session's [`crypto::Opener`] and feeding the
/// decrypted inner frames to `dispatcher` in order.
async fn run_reader_secure<S>(read: &mut S, dispatcher: &Arc<Dispatcher>, mut opener: crypto::Opener) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = read.next().await {
        let msg = msg.map_err(|e| format!("read: {e}"))?;
        match msg {
            Message::Binary(data) => {
                let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;
                if hdr.channel == wire::CHANNEL_CONTROL {
                    if is_session_ending_control(payload) {
                        return Ok(());
                    }
                    log_control(payload);
                    continue;
                }
                if hdr.channel != wire::CHANNEL_CIPHERTEXT {
                    // A fresh handshake attempt (0x02) from a different
                    // peer attaching to this pair isn't supported by a
                    // single `run_once` session — see its doc comment.
                    // Ending here lets the supervisor reconnect and
                    // handshake with whoever is attached next.
                    return Ok(());
                }
                let plaintext = opener
                    .open(&CIPHERTEXT_HEADER, payload)
                    .map_err(|e| format!("aead open: {}", crypto::error_code(e)))?;
                let frames = wire::decode_inner_all(&plaintext).map_err(|e| e.to_string())?;
                for frame in frames {
                    dispatcher.handle(frame).await;
                }
            }
            Message::Close(_) => return Ok(()),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            Message::Text(_) => {
                return Err("received a text frame; the relay protocol is binary-only".to_string());
            }
        }
    }
    Ok(())
}

/// `peer_offline` (the web client went away) and `going_away` (the relay
/// is shutting down) both end this session cleanly rather than being
/// logged and ignored — see `run_once`'s doc comment on why a single
/// session can't outlive its one peer.
fn is_session_ending_control(payload: &[u8]) -> bool {
    matches!(
        serde_json::from_slice::<ControlMsg>(payload),
        Ok(ControlMsg { t, .. }) if t == "peer_offline" || t == "going_away"
    )
}

// --- insecure (plaintext dev bridge) path — Step 4, unchanged ----------

/// Runs one connection attempt to completion: dial, hello, hello_ok, then
/// pump frames until the connection drops for any reason. Returns an
/// `Err` describing why; the caller (`relay::respawn`'s supervisor loop)
/// owns backoff and reconnection — this function never retries on its
/// own.
pub async fn run_once_insecure(
    relay_url: &str,
    pair_id: [u8; 16],
    router: Router,
    bearer_token: String,
) -> Result<(), String> {
    let url = format!("{}/v1/agent", relay_url.trim_end_matches('/'));
    let (ws_stream, _) = connect_async(&url)
        .await
        .map_err(|e| format!("connect to {url}: {e}"))?;
    let (mut write, mut read) = ws_stream.split();

    send_hello(&mut write, pair_id).await?;
    expect_control(&mut read, "hello_ok").await?;

    let (out_tx, out_rx) = mpsc::channel::<InnerFrame>(OUT_CHANNEL_CAPACITY);
    let dispatcher = Dispatcher::new(router, bearer_token, out_tx);

    let writer_task = tokio::spawn(run_writer(write, out_rx));

    let result = run_reader(&mut read, &dispatcher).await;

    writer_task.abort();
    result
}

async fn send_hello<S>(write: &mut S, pair_id: [u8; 16]) -> Result<(), String>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let pair_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair_id);
    let hello = serde_json::json!({
        "t": "hello",
        "v": 1,
        "role": "agent",
        "pair": pair_b64,
        "token": "",
    });
    let hello_bytes = serde_json::to_vec(&hello).map_err(|e| format!("encode hello: {e}"))?;
    let frame = wire::encode_outer(wire::CHANNEL_CONTROL, &hello_bytes);
    write
        .send(Message::Binary(frame.into()))
        .await
        .map_err(|e| format!("send hello: {e}"))
}

/// Reads exactly one control-channel message and confirms its `t` field
/// matches `want_type` — used only for the immediate post-hello
/// `hello_ok` check; the main read loop handles every subsequent control
/// message (`peer_online`/`peer_offline`/`error`/`going_away`) itself.
async fn expect_control<S>(read: &mut S, want_type: &str) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = read
        .next()
        .await
        .ok_or_else(|| "connection closed before hello_ok".to_string())?
        .map_err(|e| format!("read hello_ok: {e}"))?;
    let Message::Binary(data) = msg else {
        return Err("expected a binary message for hello_ok".to_string());
    };
    let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;
    if hdr.channel != wire::CHANNEL_CONTROL {
        return Err(format!(
            "expected control channel for hello_ok, got 0x{:02x}",
            hdr.channel.0
        ));
    }
    let msg: ControlMsg = serde_json::from_slice(payload).map_err(|e| e.to_string())?;
    if msg.t != want_type {
        return Err(format!("expected control {want_type:?}, got {:?}", msg.t));
    }
    Ok(())
}

/// Owns the WebSocket sink exclusively — the single writer for this
/// connection. Every outbound `InnerFrame` is wire-encoded, wrapped in a
/// channel-0x01 outer frame with no encryption (plaintext dev mode; see
/// `run_writer_secure` for the real path), and written in order.
async fn run_writer<S>(mut write: S, mut out_rx: mpsc::Receiver<InnerFrame>)
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    while let Some(frame) = out_rx.recv().await {
        let mut buf = Vec::new();
        if wire::encode_inner(&mut buf, &frame).is_err() {
            // Only a reserved-type or oversize-payload frame hits this,
            // neither of which dispatch.rs ever constructs — but drop
            // rather than crash the writer over one bad outbound frame.
            continue;
        }
        let outer = wire::encode_outer(wire::CHANNEL_CIPHERTEXT, &buf);
        if write.send(Message::Binary(outer.into())).await.is_err() {
            return;
        }
    }
}

/// Reads incoming messages until the connection ends, decoding channel
/// 0x01 payloads into inner frames and feeding them to `dispatcher` in
/// order — the sequential-call requirement `Dispatcher::handle` documents
/// is exactly what this loop provides. Control-channel messages
/// (`peer_online`/`peer_offline`/`error`/`going_away`) are logged, not
/// acted on — this is the plaintext dev bridge, which never outlives a
/// manual test run.
async fn run_reader<S>(read: &mut S, dispatcher: &Arc<Dispatcher>) -> Result<(), String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = read.next().await {
        let msg = msg.map_err(|e| format!("read: {e}"))?;
        match msg {
            Message::Binary(data) => {
                let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;
                if hdr.channel == wire::CHANNEL_CONTROL {
                    log_control(payload);
                    continue;
                }
                if hdr.channel != wire::CHANNEL_CIPHERTEXT {
                    // Only 0x00/0x01 exist in plaintext mode — 0x02
                    // (handshake) is the real path's, and anything else
                    // is a protocol violation from the relay's own peer.
                    continue;
                }
                let frames = wire::decode_inner_all(payload).map_err(|e| e.to_string())?;
                for frame in frames {
                    dispatcher.handle(frame).await;
                }
            }
            Message::Close(_) => return Ok(()),
            // Ping/Pong are answered transparently inside tungstenite's
            // own read path; nothing to do here even if the variant
            // surfaces to us. Frame(_) is a low-level raw-frame escape
            // hatch tungstenite itself never yields from a Stream — safe
            // to ignore.
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            // Spec §1: all application messages are binary; a Text frame
            // from the relay means either a bug or a different server
            // entirely on the other end of this connection — treat it the
            // same as the relay itself would (close 4400), rather than
            // silently waiting on a peer that isn't speaking the protocol.
            Message::Text(_) => {
                return Err("received a text frame; the relay protocol is binary-only".to_string());
            }
        }
    }
    Ok(())
}

fn log_control(payload: &[u8]) {
    if let Ok(msg) = serde_json::from_slice::<ControlMsg>(payload) {
        match msg.t.as_str() {
            "peer_online" => println!("amallo: relay: peer online"),
            "peer_offline" => println!("amallo: relay: peer offline"),
            "going_away" => println!("amallo: relay: shutting down, will reconnect"),
            "error" => eprintln!("amallo: relay: error: {}", msg.code),
            other => println!("amallo: relay: control message: {other}"),
        }
    }
}
