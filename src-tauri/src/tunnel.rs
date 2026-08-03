use std::sync::Arc;

use ngrok::config::ForwarderBuilder;
use ngrok::forwarder::Forwarder;
use ngrok::session::Session;
use ngrok::tunnel::{EndpointInfo, HttpTunnel, TunnelCloser};
use tauri::{AppHandle, Emitter, Manager, Wry};
use url::Url;

use crate::state::{AppState, TunnelStatus};
use crate::{secrets, tray};

pub struct TunnelHandle {
    session: Session,
    forwarder: Forwarder<HttpTunnel>,
}

/// Update status everywhere at once: state, tray menu, settings window.
pub fn set_status(app: &AppHandle<Wry>, status: TunnelStatus) {
    match &status {
        TunnelStatus::Running { url } => println!("amallo: tunnel online at {url}"),
        TunnelStatus::Error { message } => eprintln!("amallo: tunnel error: {message}"),
        _ => {}
    }
    let state = app.state::<Arc<AppState>>();
    *state.status.write().unwrap() = status.clone();
    tray::refresh(app, &status);
    let _ = app.emit("tunnel-status", &status);
}

fn friendly_error(e: impl std::fmt::Display) -> String {
    let msg = e.to_string();
    if msg.contains("ERR_NGROK_105") || msg.contains("authentication failed") {
        "ngrok rejected the authtoken — check it in Settings".into()
    } else if msg.contains("ERR_NGROK_3200") || msg.contains("not found") && msg.contains("domain")
    {
        "the static domain is not reserved for this ngrok account".into()
    } else if msg.contains("ERR_NGROK_334") || msg.contains("already online") {
        "the static domain is already in use by another agent".into()
    } else {
        msg
    }
}

pub async fn start(app: AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>().inner().clone();

    let mut guard = state.tunnel.lock().await;
    if guard.is_some() {
        return; // already running
    }

    let authtoken = match secrets::get_ngrok_token(&app) {
        Ok(Some(t)) => t,
        Ok(None) => {
            set_status(
                &app,
                TunnelStatus::Error {
                    message: "no ngrok authtoken set — open Settings".into(),
                },
            );
            return;
        }
        Err(e) => {
            set_status(&app, TunnelStatus::Error { message: e });
            return;
        }
    };

    set_status(&app, TunnelStatus::Connecting);

    let settings = state.settings();
    let local_url = format!("http://127.0.0.1:{}", settings.proxy_port);

    let result = async {
        let session = Session::builder()
            .authtoken(authtoken)
            .connect()
            .await
            .map_err(friendly_error)?;

        let mut endpoint = session.http_endpoint();
        endpoint.forwards_to("amallo -> ollama");
        if let Some(domain) = settings
            .static_domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            endpoint.domain(domain);
        }

        let forwarder = endpoint
            .listen_and_forward(Url::parse(&local_url).map_err(|e| e.to_string())?)
            .await
            .map_err(friendly_error)?;

        Ok::<_, String>((session, forwarder))
    }
    .await;

    match result {
        Ok((session, forwarder)) => {
            let url = forwarder.url().to_string();
            *guard = Some(TunnelHandle { session, forwarder });
            drop(guard);
            set_status(&app, TunnelStatus::Running { url: url.clone() });
            // ngrok can accept the tunnel session even when the account has
            // already burned its monthly request quota — those then 403 at the
            // edge and never reach the local proxy. Probe once so the console
            // (and future debugging) surfaces that clearly.
            let token = state.bearer_token();
            tauri::async_runtime::spawn(async move {
                verify_public_url(&url, &token).await;
            });
        }
        Err(message) => {
            drop(guard);
            set_status(&app, TunnelStatus::Error { message });
        }
    }
}

/// Hit the public URL once and log if ngrok (or anything else) blocks us
/// before the request reaches amallo.
async fn verify_public_url(url: &str, token: &str) {
    let probe = format!("{}/api/tags", url.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("amallo: could not build probe client: {e}");
            return;
        }
    };

    let response = match client
        .get(&probe)
        .header("Authorization", format!("Bearer {token}"))
        .header("ngrok-skip-browser-warning", "true")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("amallo: public URL probe failed — could not reach {probe}: {e}");
            return;
        }
    };

    let status = response.status();
    if status.is_success() {
        println!("amallo: public URL probe ok ({status})");
        return;
    }

    let ngrok_code = response
        .headers()
        .get("ngrok-error-code")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.text().await.unwrap_or_default();
    let body_hint = body.chars().take(200).collect::<String>().replace('\n', " ");

    match ngrok_code.as_deref() {
        Some("ERR_NGROK_727") => eprintln!(
            "amallo: public URL returns {status} (ERR_NGROK_727) — ngrok monthly HTTP request \
             limit reached; local proxy is fine, but clients hitting the tunnel will keep \
             getting 403. See https://dashboard.ngrok.com/billing"
        ),
        Some(code) => eprintln!(
            "amallo: public URL returns {status} ({code}) — request never reached the local proxy. body: {body_hint}"
        ),
        None => eprintln!(
            "amallo: public URL returns {status} — probe of {probe} failed. body: {body_hint}"
        ),
    }
}

pub async fn stop(app: AppHandle<Wry>) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let handle = state.tunnel.lock().await.take();
    if let Some(mut handle) = handle {
        // Close the endpoint with an awaited RPC so ngrok releases the domain
        // *before* we return. Relying on drop closes it asynchronously, which
        // races a fresh start() on the same static domain (ERR_NGROK_334).
        let _ = handle.forwarder.close().await;
        handle.forwarder.join().abort();
        let _ = handle.session.close().await;
    }
    set_status(&app, TunnelStatus::Stopped);
}
