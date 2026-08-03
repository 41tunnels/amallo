//! Relay pairing material and its encodings — the pair_id+PSK amallo
//! generates (see `secrets.rs`), and the `opencharui://pair?...` URI/QR
//! that get it onto a phone or browser (spec §3, §9). Mirrors web's
//! `pairing-schema.ts`, which parses exactly this string.

use base64::Engine;
use qrcode::render::svg;
use qrcode::QrCode;
use tauri::{AppHandle, Wry};

use crate::secrets;

/// Encodes the pairing URI a QR code or the "copy pairing code" tray
/// action both carry: `opencharui://pair?v=1&r=<relay_url>&i=<pair_id>&k=<psk>`.
/// `relay_url` is not percent-encoded — it never contains `&`/`=`/`#`
/// characters in practice (a plain `wss://host[:port]`), and every other
/// implementation of this spec (the relay repo's `fakeagent`, this
/// project's `web/src/shared/pairing-schema.ts`) encodes/decodes it the
/// same unencoded way, so this keeps all three consistent rather than
/// inventing a new convention only amallo would use.
pub fn encode_uri(relay_url: &str, pair_id: [u8; 16], psk: [u8; 32]) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "opencharui://pair?v=1&r={relay_url}&i={}&k={}",
        b64.encode(pair_id),
        b64.encode(psk)
    )
}

/// Renders `uri` as an SVG QR code — chosen over a raster format so the
/// PSK never round-trips through an intermediate bitmap decoder, and so
/// `qrcode` doesn't need its `image` feature (default-features = false in
/// Cargo.toml keeps that crate out of the dependency tree entirely).
pub fn render_qr_svg(uri: &str) -> Result<String, String> {
    let code = QrCode::new(uri.as_bytes()).map_err(|e| format!("failed to build QR code: {e}"))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(280, 280)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

/// Loads the persisted pairing material, generating and persisting a
/// fresh pair_id+PSK on first use.
pub fn get_or_create(app: &AppHandle<Wry>) -> Result<([u8; 16], [u8; 32]), String> {
    secrets::get_or_create_pairing(app)
}

/// Replaces the pairing material with a fresh pair_id+PSK — invalidates
/// every device paired with the old code.
pub fn regenerate(app: &AppHandle<Wry>) -> Result<([u8; 16], [u8; 32]), String> {
    secrets::regenerate_pairing(app)
}
