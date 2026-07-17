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
            set_status(&app, TunnelStatus::Running { url });
        }
        Err(message) => {
            drop(guard);
            set_status(&app, TunnelStatus::Error { message });
        }
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
