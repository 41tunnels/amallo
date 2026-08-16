//! The relay WebSocket connection itself: connect, hello, the E2E
//! handshake (spec §4), and the pump that decrypts incoming ciphertext
//! frames into a [`Dispatcher`] and encrypts outbound ones back onto the
//! wire (spec §5/§6). `run_once` is the real, production path; alongside
//! it, `run_once_insecure` is Step 4's plaintext dev bridge — channel
//! 0x01 carries raw wire-encoded bytes with no AEAD wrapping at all, only
//! reachable via `AMALLO_RELAY_INSECURE=1`, and MUST NEVER be used
//! against a production relay.
//!
//! # One connection, two lanes
//!
//! `run_once` serves both the E2E-paired browser (sealed, channel 0x01)
//! and the OpenAI-compatible endpoint (plain, channel 0x03) over a single
//! socket. The two share the wire and nothing else: each has its own
//! [`Dispatcher`] built with its own [`policy::PolicyMode`], so a leaked
//! API key cannot reach model management or the sync store no matter what
//! it puts on the plain lane.
//!
//! The structural point is that the *connection* now outlives the
//! *session*. A browser attaching starts a handshake; a browser leaving
//! retires the session and nothing more. That is what lets the plain lane
//! serve with no browser ever attached, and keeps a closed tab from
//! interrupting third-party inference mid-stream.

use std::sync::Arc;

use aws_lc_rs::digest;
use axum::Router;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::Deserialize;
use tauri::{AppHandle, Wry};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::relay::crypto;
use crate::relay::dispatch::Dispatcher;
use crate::relay::policy;
use crate::relay::set_status;
use crate::relay::wire::{self, InnerFrame};
use crate::state::RelayStatus;

/// Bound on the outbound-frame channel between the Dispatcher (and its
/// per-request response-streaming tasks) and the single writer task that
/// owns the WebSocket sink and, in the real path, the [`crypto::Sealer`]
/// — spec §5.1's "exactly one sealing point per direction" rule, enforced
/// structurally: nothing but the writer task ever calls `seal`.
const OUT_CHANNEL_CAPACITY: usize = 64;

/// Bound on the two handshake-carrying channels. Small on purpose: a
/// handshake is four frames total, and a peer that floods 0x02 frames
/// should apply backpressure to the read loop rather than accumulate.
const HANDSHAKE_CHANNEL_CAPACITY: usize = 4;

/// How many ciphertext frames may be held while a handshake finishes.
///
/// This buffer exists because the peer legitimately sends its first
/// request the instant it has verified our CONFIRM, which is *before*
/// our handshake task has reported completion back to the read loop.
/// Those frames are already authenticated by the session that is about
/// to be installed, so dropping them would strand a request the peer
/// considers sent, and rejecting them would break every first request
/// that happens to win the race. A handful is plenty: the peer cannot
/// get far ahead without a response, and anything past this bound is a
/// flood rather than a race.
const MAX_PENDING_CIPHERTEXT: usize = 16;

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

/// Why a connection ended, as far as the supervisor is concerned.
///
/// The distinction exists because one of the two is not a failure at all:
/// [`ConnEnd::Redial`] is this connection asking to be replaced *now*,
/// which must not be paid for with backoff or a visible offline blip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnEnd {
    /// An ordinary end — the relay went away, the socket closed, or a
    /// `going_away` arrived. The supervisor reconnects with backoff.
    Closed,
    /// The hello needs to be re-sent because a lane this socket does not
    /// carry has been switched on. Only the hello can create the HTTP
    /// lane (spec §11.3), so there is nothing to publish in place and the
    /// supervisor should redial immediately — see [`run_reader_dual`].
    Redial,
}

// --- real (encrypted) path ---------------------------------------------

/// Commands to the single writer task. Everything that reaches the
/// WebSocket sink goes through here, so the sink keeps exactly one owner
/// and the [`crypto::Sealer`] exactly one user (spec §5.1) even though
/// the sealer is now replaced on every new session.
enum WriterCmd {
    /// A raw handshake payload (channel 0x02), sent unsealed — the
    /// session it will produce does not exist yet.
    Handshake(Vec<u8>),
    /// A control-channel (0x00) message. Post-hello, the only one v1
    /// defines is `rekey` (spec §11.3).
    Control(Vec<u8>),
    /// A session became established: install its sealer and start
    /// draining its outbound frames. The receiver travels *with* the
    /// sealer deliberately — that is what makes the ordering safe, since
    /// a frame cannot reach the writer ahead of the sealer that has to
    /// seal it.
    SessionUp {
        sealer: Box<crypto::Sealer>,
        frames: mpsc::Receiver<InnerFrame>,
    },
    /// The web peer went away: drop the sealer and stop draining.
    SessionDown,
}

/// The writer's half of a live E2E session.
struct SessionWriter {
    sealer: crypto::Sealer,
    frames: mpsc::Receiver<InnerFrame>,
}

/// One iteration of the writer loop, hoisted out of the `select!` so the
/// borrow of `session` ends before a handler reassigns it.
enum WriterStep {
    Cmd(Option<WriterCmd>),
    Sealed(Option<InnerFrame>),
    Plain(Option<InnerFrame>),
}

/// The E2E session as a state *inside* the connection, rather than as the
/// connection's own lifecycle. This is the whole point of the dual-lane
/// design: `Idle` is a perfectly healthy steady state in which the plain
/// lane keeps serving, so the OpenAI endpoint no longer depends on a
/// browser being attached.
enum Session {
    Idle,
    Handshaking {
        hs_tx: mpsc::Sender<Vec<u8>>,
        /// Ciphertext that arrived before the handshake task reported in
        /// — see [`MAX_PENDING_CIPHERTEXT`]. Drained, in order, the
        /// moment the session is installed.
        pending: Vec<Vec<u8>>,
    },
    Established { opener: crypto::Opener, dispatcher: Arc<Dispatcher> },
}

/// Everything the read loop needs to start and retire sessions, bundled
/// so the loop's own signature stays readable.
struct ConnCtx<'a, F: Fn(RelayStatus)> {
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: &'a Router,
    bearer_token: &'a str,
    cmd_tx: &'a mpsc::Sender<WriterCmd>,
    /// The inference-only dispatcher. Always built, even when the
    /// endpoint is off, so switching it on mid-connection needs nothing
    /// more than a rekey. Whether a 0x03 frame is actually served is
    /// gated at runtime on the current key — see `run_reader_dual`.
    http: &'a Arc<Dispatcher>,
    on_status: &'a F,
}

/// Builds a `rekey` control (spec §11.3). An empty hash tells the relay
/// to stop resolving this connection's key entirely, which is how the
/// endpoint is switched off without disturbing the paired browser.
fn rekey_payload(api_key: Option<&str>) -> Vec<u8> {
    let token_hash = api_key.map(token_hash_b64).unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({ "t": "rekey", "token_hash": token_hash }))
        .expect("rekey payload is a plain JSON object")
}

/// Runs one *connection* to completion: dial, hello, then serve both
/// lanes until the socket ends for any reason. Returns `Ok(())` for an
/// ordinary end (relay went away, socket closed) and `Err` describing a
/// real failure; either way the caller (`relay::supervise`) owns backoff
/// and reconnection — this function never retries on its own.
///
/// What changed with the dual-lane merge: this no longer waits for a web
/// peer before it is useful, and no longer returns when one leaves. A
/// peer attaching starts a session; a peer leaving retires it; the
/// connection outlives both, so re-pairing costs a handshake rather than
/// a full reconnect, and third-party inference on the plain lane is
/// never interrupted by a closed browser tab.
///
/// `api_key_rx` carries the API key the OpenAI-compatible endpoint
/// currently accepts, or `None` when it is off. A `Some` value makes the
/// hello a `mode:"dual"` one carrying the key's hash, which is what tells
/// the relay to route HTTP traffic down this same socket. Changes
/// published while the connection is up are forwarded as a `rekey`
/// control rather than forcing a reconnect (spec §11.3), so rotating a
/// key or toggling the endpoint never interrupts a paired browser.
///
/// The one exception is a connection that helloed *without* a key: it has
/// no HTTP lane for a `rekey` to act on, so switching the endpoint on
/// returns [`ConnEnd::Redial`] instead. See [`run_reader_dual`].
pub async fn run_once(
    app: &AppHandle<Wry>,
    relay_url: &str,
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: Router,
    bearer_token: String,
    api_key_rx: watch::Receiver<Option<String>>,
) -> Result<ConnEnd, String> {
    run_once_with_status(relay_url, pair_id, psk, router, bearer_token, api_key_rx, |status| {
        set_status(app, status)
    })
    .await
}

/// The actual connection logic, with no Tauri dependency at all —
/// `on_status` is called at each status transition instead of this
/// function reaching into an `AppHandle` itself. `run_once` is a thin
/// wrapper over this for the real supervisor; this split is what lets the
/// connection logic run and be verified (e.g. against a real deployed
/// relay, from a plain `main()`) without standing up a full Tauri app.
pub async fn run_once_with_status(
    relay_url: &str,
    pair_id: [u8; 16],
    psk: [u8; 32],
    router: Router,
    bearer_token: String,
    mut api_key_rx: watch::Receiver<Option<String>>,
    on_status: impl Fn(RelayStatus),
) -> Result<ConnEnd, String> {
    let url = format!("{}/v1/agent", relay_url.trim_end_matches('/'));
    let (ws_stream, _) = connect_async(&url)
        .await
        .map_err(|e| format!("connect to {url}: {e}"))?;
    let (mut write, mut read) = ws_stream.split();

    // `borrow_and_update` marks this value seen, so the reader's watch arm
    // only fires on changes made after the hello went out.
    let api_key = api_key_rx.borrow_and_update().clone();

    send_hello(&mut write, pair_id, api_key.as_deref()).await?;
    expect_control(&mut read, "hello_ok").await?;

    // Past hello the connection is live and stays live. `Waiting` here
    // means "connected, no browser paired yet" — which is also when the
    // plain lane is already serving, if it is enabled.
    on_status(RelayStatus::Waiting);

    let (cmd_tx, cmd_rx) = mpsc::channel::<WriterCmd>(OUT_CHANNEL_CAPACITY);
    let (http_tx, http_rx) = mpsc::channel::<InnerFrame>(OUT_CHANNEL_CAPACITY);

    // Built once for the whole connection, with the strictly smaller
    // allowlist. Kept a separate object from the per-session E2E
    // dispatcher on purpose: the socket merges, the permission boundary
    // does not — see `policy::PolicyMode`.
    //
    // Built even when the endpoint is off, so switching it on later needs
    // only a rekey rather than a reconnect. Whether a 0x03 frame is
    // actually served is gated on the current key inside the read loop.
    let http_dispatcher = Dispatcher::with_policy(
        router.clone(),
        bearer_token.clone(),
        http_tx.clone(),
        policy::PolicyMode::Http,
    );

    let writer_task = tokio::spawn(run_writer_dual(write, cmd_rx, http_rx));

    let ctx = ConnCtx {
        pair_id,
        psk,
        router: &router,
        bearer_token: &bearer_token,
        cmd_tx: &cmd_tx,
        http: &http_dispatcher,
        on_status: &on_status,
    };
    let result = run_reader_dual(&mut read, ctx, &mut api_key_rx, api_key).await;

    // `http_tx` stayed alive for the reader's whole life so the writer's
    // plain arm never observed a closed channel while the connection was
    // up — including when the endpoint is disabled and nothing ever sends.
    drop(http_tx);
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
///
/// Runs as its own task, driven by channels rather than by the socket:
/// the read loop owns the socket now and forwards inbound 0x02 payloads
/// into `hs_rx`, while outbound frames go out through the writer via
/// `cmd_tx`. That indirection is deliberate — it keeps this function a
/// straight-line sequence of the four spec steps instead of a state
/// machine spread across the read loop.
async fn perform_handshake(
    cmd_tx: &mpsc::Sender<WriterCmd>,
    hs_rx: &mut mpsc::Receiver<Vec<u8>>,
    pair_id: [u8; 16],
    psk: [u8; 32],
) -> Result<HandshakeResult, String> {
    let agent_eph = crypto::Ephemeral::generate().map_err(|e| format!("generate ephemeral: {}", crypto::error_code(e)))?;
    let mut agent_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut agent_nonce);

    let hello_agent = crypto::build_hello(&psk, crypto::ROLE_AGENT, pair_id, agent_eph.public_key_bytes(), agent_nonce)
        .map_err(|e| format!("build hello: {}", crypto::error_code(e)))?;
    send_handshake(cmd_tx, &hello_agent).await?;

    let hello_web = expect_handshake(hs_rx).await?;
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
    send_handshake(cmd_tx, &confirm_agent).await?;

    let confirm_web = expect_handshake(hs_rx).await?;
    crypto::verify_confirm(&session, &confirm_web, crypto::ROLE_CLIENT)
        .map_err(|e| format!("verify peer confirm: {}", crypto::error_code(e)))?;

    Ok(HandshakeResult {
        k_a2w: session.k_a2w,
        k_w2a: session.k_w2a,
        np_a2w: session.np_a2w,
        np_w2a: session.np_w2a,
    })
}

/// Queues one handshake payload for the writer. The socket itself is
/// owned by the writer task, so even the handshake — which predates any
/// session — goes out through the same single sink owner.
async fn send_handshake(cmd_tx: &mpsc::Sender<WriterCmd>, payload: &[u8]) -> Result<(), String> {
    cmd_tx
        .send(WriterCmd::Handshake(payload.to_vec()))
        .await
        .map_err(|_| "writer task ended during handshake".to_string())
}

/// Waits for the next inbound handshake payload, which the read loop
/// forwards here after seeing a 0x02 frame. A closed channel means the
/// read loop retired this handshake (peer left, or a newer one started).
async fn expect_handshake(hs_rx: &mut mpsc::Receiver<Vec<u8>>) -> Result<Vec<u8>, String> {
    hs_rx
        .recv()
        .await
        .ok_or_else(|| "handshake abandoned before it completed".to_string())
}

/// Owns the WebSocket sink exclusively, and with it the current
/// [`crypto::Sealer`] — still the single writer/sealing point for the
/// connection (spec §5.1), now with a sealer that is installed and
/// retired as sessions come and go rather than fixed for the socket's
/// lifetime.
///
/// Sealed frames go out on channel 0x01, plain ones on 0x03, and
/// handshake payloads on 0x02. Nothing else can reach the sink.
async fn run_writer_dual<S>(
    mut write: S,
    mut cmd_rx: mpsc::Receiver<WriterCmd>,
    mut http_rx: mpsc::Receiver<InnerFrame>,
) where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let mut session: Option<SessionWriter> = None;

    loop {
        // Two `select!`s rather than one with an optional arm: the
        // handlers below reassign `session`, which they could not do
        // while a single `select!` held a borrow of it for the whole
        // statement.
        let step = if let Some(s) = session.as_mut() {
            tokio::select! {
                cmd = cmd_rx.recv() => WriterStep::Cmd(cmd),
                frame = s.frames.recv() => WriterStep::Sealed(frame),
                frame = http_rx.recv() => WriterStep::Plain(frame),
            }
        } else {
            tokio::select! {
                cmd = cmd_rx.recv() => WriterStep::Cmd(cmd),
                frame = http_rx.recv() => WriterStep::Plain(frame),
            }
        };

        match step {
            // The read loop dropped its sender: the connection is over.
            WriterStep::Cmd(None) => return,
            WriterStep::Cmd(Some(WriterCmd::Handshake(payload))) => {
                let outer = wire::encode_outer(wire::CHANNEL_HANDSHAKE, &payload);
                if write.send(Message::Binary(outer.into())).await.is_err() {
                    return;
                }
            }
            WriterStep::Cmd(Some(WriterCmd::Control(payload))) => {
                let outer = wire::encode_outer(wire::CHANNEL_CONTROL, &payload);
                if write.send(Message::Binary(outer.into())).await.is_err() {
                    return;
                }
            }
            WriterStep::Cmd(Some(WriterCmd::SessionUp { sealer, frames })) => {
                session = Some(SessionWriter { sealer: *sealer, frames });
            }
            WriterStep::Cmd(Some(WriterCmd::SessionDown)) => session = None,
            // The session's dispatcher was dropped — the same event as
            // SessionDown, just observed from the other end.
            WriterStep::Sealed(None) => session = None,
            WriterStep::Sealed(Some(frame)) => {
                let Some(s) = session.as_mut() else { continue };
                let mut buf = Vec::new();
                if wire::encode_inner(&mut buf, &frame).is_err() {
                    // Only a reserved-type or oversize-payload frame hits
                    // this, neither of which dispatch.rs ever constructs —
                    // drop rather than crash the writer over one frame.
                    continue;
                }
                let sealed = match s.sealer.seal(&CIPHERTEXT_HEADER, &buf) {
                    Ok(sealed) => sealed,
                    // Counter exhaustion (2^64 frames — never happens in
                    // practice) or an internal AEAD failure: this session
                    // can no longer seal safely. Retire the session, not
                    // the connection — the plain lane is unaffected and
                    // the next handshake starts clean.
                    Err(_) => {
                        session = None;
                        continue;
                    }
                };
                let outer = wire::encode_outer(wire::CHANNEL_CIPHERTEXT, &sealed);
                if write.send(Message::Binary(outer.into())).await.is_err() {
                    return;
                }
            }
            WriterStep::Plain(None) => return,
            WriterStep::Plain(Some(frame)) => {
                let mut buf = Vec::new();
                if wire::encode_inner(&mut buf, &frame).is_err() {
                    continue;
                }
                let outer = wire::encode_outer(wire::CHANNEL_PLAIN, &buf);
                if write.send(Message::Binary(outer.into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Spawns a handshake for a newly-attached peer and returns the state
/// that routes inbound 0x02 frames to it.
fn start_handshake<F: Fn(RelayStatus)>(
    ctx: &ConnCtx<'_, F>,
    hs_done_tx: &mpsc::Sender<Result<HandshakeResult, String>>,
) -> Session {
    let (hs_tx, mut hs_rx) = mpsc::channel::<Vec<u8>>(HANDSHAKE_CHANNEL_CAPACITY);
    let cmd_tx = ctx.cmd_tx.clone();
    let done = hs_done_tx.clone();
    let pair_id = ctx.pair_id;
    let psk = ctx.psk;
    tokio::spawn(async move {
        let result = perform_handshake(&cmd_tx, &mut hs_rx, pair_id, psk).await;
        let _ = done.send(result).await;
    });
    Session::Handshaking { hs_tx, pending: Vec::new() }
}

fn control_type(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<ControlMsg>(payload).ok().map(|m| m.t)
}

/// The connection's single read loop. Runs until the socket ends, routing
/// each frame by its channel byte and carrying the E2E session through
/// its own lifecycle underneath.
///
/// The invariant that matters here: a 0x01 frame is only ever opened in
/// `Established`, and a 0x03 frame only ever reaches the inference-only
/// dispatcher. The socket is shared; the two permission surfaces are not.
async fn run_reader_dual<S, F>(
    read: &mut S,
    ctx: ConnCtx<'_, F>,
    api_key_rx: &mut watch::Receiver<Option<String>>,
    initial_key: Option<String>,
) -> Result<ConnEnd, String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    F: Fn(RelayStatus),
{
    let mut session = Session::Idle;
    // Whether the hello asked for the HTTP lane, and so whether the relay
    // has anything for a `rekey` to re-index. A connection that helloed
    // without a key is a plain E2E agent as far as the relay is
    // concerned, and spec §11.3 has it *ignore* a rekey arriving there —
    // which is why switching the endpoint on has to redial rather than
    // publish. Once the lane exists it stays for the socket's life:
    // switching off unregisters the entry but keeps it rekeyable, so
    // off/on cycles and key rotation still cost nothing.
    let has_http_lane = initial_key.is_some();
    // What the hello published. Kept in step with the watch so a 0x03
    // frame is only served while the endpoint is actually on.
    let mut api_key = initial_key;
    // Cleared once the sender is gone (no Tauri app behind it, e.g. the
    // smoke binary), so the watch arm stops being polled.
    let mut watching_key = true;
    // Handshake tasks report back here. The sender is held for the whole
    // loop, so this arm never observes a closed channel while the
    // connection is up.
    let (hs_done_tx, mut hs_done_rx) =
        mpsc::channel::<Result<HandshakeResult, String>>(HANDSHAKE_CHANNEL_CAPACITY);

    loop {
        let data = tokio::select! {
            // Biased so a finished handshake is always installed before
            // another frame is read. That keeps `pending` empty in the
            // common case; it is not what makes the race safe, since the
            // task may simply not have reported in yet.
            biased;

            // Republishing the key hash in place (spec §11.3). This is
            // what keeps revoking a key or toggling the endpoint from
            // dropping the socket a paired browser is mid-chat on.
            changed = api_key_rx.changed(), if watching_key => {
                if changed.is_err() {
                    watching_key = false;
                    continue;
                }
                api_key = api_key_rx.borrow_and_update().clone();
                if !has_http_lane {
                    // Nothing to rekey: this socket helloed as a plain E2E
                    // agent. Turning the endpoint *on* needs a new hello,
                    // so hand back to the supervisor to redial at once —
                    // without this the user is left with an endpoint the
                    // UI calls enabled and the relay answers 401 for,
                    // until something else happens to reconnect.
                    if api_key.is_some() {
                        println!(
                            "amallo: relay: openai endpoint switched on; redialling to publish it"
                        );
                        return Ok(ConnEnd::Redial);
                    }
                    // Switched off on a connection that never had the
                    // lane — already the state the relay is in.
                    continue;
                }
                let payload = rekey_payload(api_key.as_deref());
                if ctx.cmd_tx.send(WriterCmd::Control(payload)).await.is_err() {
                    return Ok(ConnEnd::Closed);
                }
                match &api_key {
                    Some(_) => println!("amallo: relay: openai endpoint key republished"),
                    None => println!("amallo: relay: openai endpoint switched off"),
                }
                continue;
            }

            Some(result) = hs_done_rx.recv() => {
                match result {
                    Ok(hr) => {
                        let sealer = crypto::Sealer::new(&hr.k_a2w, &hr.np_a2w)
                            .map_err(|e| format!("build sealer: {}", crypto::error_code(e)))?;
                        let mut opener = crypto::Opener::new(&hr.k_w2a, &hr.np_w2a)
                            .map_err(|e| format!("build opener: {}", crypto::error_code(e)))?;
                        // A fresh dispatcher per session: the previous
                        // one's in-flight streams belong to a peer that is
                        // gone and can never be answered.
                        let (frames_tx, frames_rx) = mpsc::channel::<InnerFrame>(OUT_CHANNEL_CAPACITY);
                        let dispatcher = Dispatcher::new(
                            ctx.router.clone(),
                            ctx.bearer_token.to_string(),
                            frames_tx,
                        );
                        let up = WriterCmd::SessionUp { sealer: Box::new(sealer), frames: frames_rx };
                        if ctx.cmd_tx.send(up).await.is_err() {
                            return Ok(ConnEnd::Closed);
                        }

                        // Anything the peer sent between verifying our
                        // CONFIRM and this moment. Opened first and in
                        // arrival order — the AEAD nonce sequence leaves
                        // no freedom about either.
                        let buffered = match std::mem::replace(&mut session, Session::Idle) {
                            Session::Handshaking { pending, .. } => pending,
                            _ => Vec::new(),
                        };
                        for payload in buffered {
                            // Unlike a frame that arrives *after* the
                            // session is installed, one held from before
                            // it is not necessarily meant for it: a peer
                            // that was mid-request when a redial displaced
                            // the previous connection can have sealed
                            // these under the session that just died, and
                            // they land here carrying that session's
                            // counter. Dropping those is both safe (they
                            // failed to authenticate, so nothing is acted
                            // on) and necessary — treating them as fatal
                            // would kill a healthy connection over frames
                            // the peer has already given up on, and cost
                            // the user a full reconnect on both ends.
                            let plaintext = match opener.open(&CIPHERTEXT_HEADER, &payload) {
                                Ok(plaintext) => plaintext,
                                Err(e) => {
                                    eprintln!(
                                        "amallo: relay: dropping a frame held from the previous session: {}",
                                        crypto::error_code(e)
                                    );
                                    continue;
                                }
                            };
                            for frame in wire::decode_inner_all(&plaintext).map_err(|e| e.to_string())? {
                                dispatcher.handle(frame).await;
                            }
                        }

                        session = Session::Established { opener, dispatcher };
                        (ctx.on_status)(RelayStatus::Online);
                        println!("amallo: relay: session established");
                    }
                    Err(e) => {
                        // A failed handshake retires the session and
                        // nothing else — the connection and the plain lane
                        // both keep running, and the next peer_online
                        // simply tries again.
                        eprintln!("amallo: relay: handshake failed: {e}");
                        session = Session::Idle;
                        let _ = ctx.cmd_tx.send(WriterCmd::SessionDown).await;
                        (ctx.on_status)(RelayStatus::Waiting);
                    }
                }
                continue;
            }

            incoming = read.next() => {
                let Some(msg) = incoming else { return Ok(ConnEnd::Closed) };
                match msg.map_err(|e| format!("read: {e}"))? {
                    Message::Binary(data) => data,
                    Message::Close(_) => return Ok(ConnEnd::Closed),
                    // The relay pings every ~30s (spec §7) and an idle
                    // connection now routinely outlives many of those.
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                    Message::Text(_) => {
                        return Err("received a text frame; the relay protocol is binary-only".to_string())
                    }
                }
            }
        };

        let (hdr, payload) = wire::parse_outer(&data).map_err(|e| e.to_string())?;

        if hdr.channel == wire::CHANNEL_CONTROL {
            match control_type(payload).as_deref() {
                Some("peer_online") => {
                    println!("amallo: relay: peer online, starting handshake");
                    session = start_handshake(&ctx, &hs_done_tx);
                }
                Some("peer_offline") => {
                    println!("amallo: relay: peer offline, session retired");
                    session = Session::Idle;
                    let _ = ctx.cmd_tx.send(WriterCmd::SessionDown).await;
                    (ctx.on_status)(RelayStatus::Waiting);
                }
                // The relay is going down; the supervisor reconnects.
                Some("going_away") => {
                    println!("amallo: relay: shutting down, will reconnect");
                    return Ok(ConnEnd::Closed);
                }
                _ => log_control(payload),
            }
            continue;
        }

        if hdr.channel == wire::CHANNEL_HANDSHAKE {
            // Starting a handshake on a bare 0x02 covers the case where a
            // peer's HELLO overtakes (or replaces) the peer_online that
            // should have preceded it — without this, a re-pair could
            // strand the session in Idle with no way back.
            if !matches!(session, Session::Handshaking { .. }) {
                session = start_handshake(&ctx, &hs_done_tx);
            }
            let abandoned = match &session {
                Session::Handshaking { hs_tx, .. } => hs_tx.send(payload.to_vec()).await.is_err(),
                _ => false,
            };
            if abandoned {
                session = Session::Idle;
            }
            continue;
        }

        if hdr.channel == wire::CHANNEL_CIPHERTEXT {
            // Mid-handshake: the session that will authenticate this is
            // moments away, so hold the frame rather than lose it.
            if let Session::Handshaking { pending, .. } = &mut session {
                if pending.len() >= MAX_PENDING_CIPHERTEXT {
                    return Err(
                        "too many ciphertext frames arrived before the session was established"
                            .to_string(),
                    );
                }
                pending.push(payload.to_vec());
                continue;
            }
            let Session::Established { opener, dispatcher } = &mut session else {
                // Idle: no session, and none coming. There is no key to
                // authenticate this with, so it ends the connection rather
                // than being skipped — the one case where tolerating a
                // frame would mean acting on unauthenticated data.
                return Err("ciphertext frame arrived with no established session".to_string());
            };
            let plaintext = opener
                .open(&CIPHERTEXT_HEADER, payload)
                .map_err(|e| format!("aead open: {}", crypto::error_code(e)))?;
            let frames = wire::decode_inner_all(&plaintext).map_err(|e| e.to_string())?;
            for frame in frames {
                dispatcher.handle(frame).await;
            }
            continue;
        }

        if hdr.channel == wire::CHANNEL_PLAIN {
            if api_key.is_none() {
                // No key published, so the relay should not be routing
                // HTTP traffic here — most likely a request that was
                // already in flight when the endpoint was switched off.
                // Ignore rather than close: a stale frame must not cost
                // the user their pairing.
                eprintln!("amallo: relay: plain frame received with the OpenAI endpoint disabled");
                continue;
            }
            let frames = wire::decode_inner_all(payload).map_err(|e| e.to_string())?;
            for frame in frames {
                ctx.http.handle(frame).await;
            }
            continue;
        }

        return Err(format!("unexpected channel 0x{:02x}", hdr.channel.0));
    }
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

    send_hello(&mut write, pair_id, None).await?;
    expect_control(&mut read, "hello_ok").await?;

    let (out_tx, out_rx) = mpsc::channel::<InnerFrame>(OUT_CHANNEL_CAPACITY);
    let dispatcher = Dispatcher::new(router, bearer_token, out_tx);

    let writer_task = tokio::spawn(run_writer(write, out_rx));

    let result = run_reader(&mut read, &dispatcher).await;

    writer_task.abort();
    result
}

/// Sends the agent hello. With `api_key` set this is a `mode:"dual"`
/// hello carrying the key's hash, which asks the relay to route the
/// OpenAI endpoint's traffic down this same socket; without it, the
/// `mode` field is omitted entirely so the hello stays byte-identical to
/// the pre-merge one and older relays keep treating it as a plain E2E
/// agent.
async fn send_hello<S>(write: &mut S, pair_id: [u8; 16], api_key: Option<&str>) -> Result<(), String>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let pair_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair_id);
    let mut hello = serde_json::json!({
        "t": "hello",
        "v": 1,
        "role": "agent",
        "pair": pair_b64,
        "token": "",
    });
    if let Some(key) = api_key {
        let obj = hello.as_object_mut().expect("hello is a JSON object");
        obj.insert("mode".to_string(), serde_json::json!("dual"));
        obj.insert("token_hash".to_string(), serde_json::json!(token_hash_b64(key)));
    }
    let hello = hello;
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
    loop {
        let msg = read
            .next()
            .await
            .ok_or_else(|| "connection closed before hello_ok".to_string())?
            .map_err(|e| format!("read hello_ok: {e}"))?;
        let data = match msg {
            Message::Binary(data) => data,
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => return Err("connection closed before hello_ok".to_string()),
            Message::Text(_) => {
                return Err("received a text frame; the relay protocol is binary-only".to_string())
            }
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
        return Ok(());
    }
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

// --- OpenAI-compatible HTTP endpoint (spec §11) ------------------------

/// `base64url(SHA-256(api_key))` — what the agent publishes to the relay
/// so it can route by key without ever storing one. The relay still sees
/// the key in flight on every request; hashing bounds what a leaked index
/// or heap dump is worth, not what a live relay can do.
pub fn token_hash_b64(api_key: &str) -> String {
    let d = digest::digest(&digest::SHA256, api_key.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d.as_ref())
}
