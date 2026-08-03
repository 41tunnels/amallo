//! The relay WebSocket connection itself: connect, hello, and the pump
//! that decodes incoming inner frames into a [`Dispatcher`] and encodes
//! outbound ones back onto the wire. Plaintext only in this step (spec
//! §4/§5's E2E handshake and AEAD sealing land in Step 5) — every outbound
//! frame here goes out on channel 0x01 as raw wire-encoded bytes, which is
//! exactly the shape `AMALLO_RELAY_INSECURE=1` describes and MUST NEVER be
//! used against a production relay once Step 5 lands.

use std::sync::Arc;

use axum::Router;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::relay::dispatch::Dispatcher;
use crate::relay::wire::{self, InnerFrame};

/// Bound on the outbound-frame channel between the Dispatcher (and its
/// per-request response-streaming tasks) and the single writer task that
/// owns the WebSocket sink. This is the same "single sealing/writing
/// point per direction" discipline the relay spec requires once Step 5
/// adds AEAD — enforced here structurally even before there's a cipher to
/// protect, so the writer task doesn't need to change shape later.
const OUT_CHANNEL_CAPACITY: usize = 64;

#[derive(Deserialize)]
struct ControlMsg {
    t: String,
    #[serde(default)]
    code: String,
}

/// Runs one connection attempt to completion: dial, hello, hello_ok, then
/// pump frames until the connection drops for any reason. Returns an
/// `Err` describing why; the caller (`relay::respawn`'s supervisor loop)
/// owns backoff and reconnection — this function never retries on its
/// own.
pub async fn run_once(
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
/// channel-0x01 outer frame with no encryption (plaintext dev mode; Step
/// 5 replaces the middle step with `Sealer::seal`), and written in order.
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
/// acted on yet — Step 6/7 wires these into `RelayStatus` and the tray.
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
                    // (handshake) is Step 5's, and anything else is a
                    // protocol violation from the relay's own peer.
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
