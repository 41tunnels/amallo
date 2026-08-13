use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Wry};

/// Secrets are kept in a single JSON file in amallo's data dir, locked to the
/// current user with `0600` permissions (the same approach the AWS CLI and
/// Docker use for their tokens). Not encrypted at rest — see the README.
#[derive(Default, Serialize, Deserialize)]
struct SecretFile {
    #[serde(default)]
    bearer_token: String,
    /// Relay pairing material (spec §3, §4.2): a 16-byte pair_id and a
    /// 32-byte PSK, base64url-encoded for JSON storage. `#[serde(default)]`
    /// so an existing secrets.json without these fields loads cleanly —
    /// `get_or_create_pairing` fills them in on first use, same as
    /// `bearer_token`.
    #[serde(default)]
    relay_pair_id: String,
    #[serde(default)]
    relay_psk: String,
    /// The API key third-party OpenAI-compatible clients present to the
    /// relay's HTTP endpoint (spec §11). Unlike `bearer_token` (which
    /// never leaves this machine) this one is handed to other people's
    /// software, so it is regenerable independently and the relay only
    /// ever learns its SHA-256.
    #[serde(default)]
    openai_api_key: String,
}

fn secrets_path(app: &AppHandle<Wry>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {e}"))?;
    Ok(dir.join("secrets.json"))
}

fn load(app: &AppHandle<Wry>) -> Result<SecretFile, String> {
    let path = secrets_path(app)?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("secrets file is corrupt ({e}) — delete {path:?} to reset")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SecretFile::default()),
        Err(e) => Err(format!("could not read secrets file: {e}")),
    }
}

fn store(app: &AppHandle<Wry>, secrets: &SecretFile) -> Result<(), String> {
    let path = secrets_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create data dir: {e}"))?;
    }
    let json = serde_json::to_vec_pretty(secrets).map_err(|e| e.to_string())?;
    write_private(&path, &json)
}

/// Write `data` to `path`, ensuring the file is only readable by the owner.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("could not write secrets file: {e}"))?;
        file.write_all(data)
            .map_err(|e| format!("could not write secrets file: {e}"))?;
        // `mode` only applies on creation; enforce it if the file pre-existed.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not set secrets file permissions: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        // On Windows the data dir under %APPDATA% is already per-user; ACL
        // hardening beyond that is out of scope for v1.
        fs::write(path, data).map_err(|e| format!("could not write secrets file: {e}"))?;
    }
    Ok(())
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load the proxy bearer token, generating and persisting one on first launch.
pub fn get_or_create_bearer_token(app: &AppHandle<Wry>) -> Result<String, String> {
    let mut secrets = load(app)?;
    if secrets.bearer_token.is_empty() {
        secrets.bearer_token = generate_token();
        store(app, &secrets)?;
    }
    Ok(secrets.bearer_token)
}

/// Replace the bearer token with a fresh one and persist it.
pub fn regenerate_bearer_token(app: &AppHandle<Wry>) -> Result<String, String> {
    let mut secrets = load(app)?;
    secrets.bearer_token = generate_token();
    store(app, &secrets)?;
    Ok(secrets.bearer_token)
}

/// `41t_` is the 41tunnels key prefix — the same convention as Stripe's
/// `sk_`, GitHub's `ghp_`, and Slack's `xoxb-`.
///
/// The prefix earns its four characters mainly through secret scanning:
/// these keys are pasted into *other people's* config files (`.cursor/`,
/// `.continue/config.json`, compose files) which routinely get committed,
/// and a fixed prefix plus known length is a pattern GitHub push
/// protection and gitleaks can match. A bare base64 blob is unmatchable,
/// so a leak would simply sit in a public repo unnoticed. It also lets a
/// user tell this apart from an OpenAI `sk-` key at a glance, and makes a
/// key recognizable in a support screenshot.
///
/// Nothing depends on the prefix: the relay hashes whatever string
/// arrives and never inspects its shape, and path disambiguation comes
/// from the reserved-segment check, not from this. 32 random bytes is
/// well past the 128-bit floor a publicly-reachable credential needs.
fn generate_openai_key() -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("41t_{}", b64.encode(generate_bytes::<32>()))
}

/// Load the OpenAI-endpoint API key, generating and persisting one on
/// first use.
pub fn get_or_create_openai_key(app: &AppHandle<Wry>) -> Result<String, String> {
    let mut secrets = load(app)?;
    if secrets.openai_api_key.is_empty() {
        secrets.openai_api_key = generate_openai_key();
        store(app, &secrets)?;
    }
    Ok(secrets.openai_api_key)
}

/// Replace the OpenAI-endpoint API key. Every client configured with the
/// old key stops working as soon as amallo reconnects with the new hash —
/// which is the point: this is the revoke button for a leaked key.
pub fn regenerate_openai_key(app: &AppHandle<Wry>) -> Result<String, String> {
    let mut secrets = load(app)?;
    secrets.openai_api_key = generate_openai_key();
    store(app, &secrets)?;
    Ok(secrets.openai_api_key)
}

fn generate_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn encode_pairing(pair_id: [u8; 16], psk: [u8; 32]) -> (String, String) {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (b64.encode(pair_id), b64.encode(psk))
}

fn decode_pairing(pair_id_b64: &str, psk_b64: &str) -> Result<([u8; 16], [u8; 32]), String> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pair_id_bytes = b64
        .decode(pair_id_b64)
        .map_err(|e| format!("secrets file has an invalid relay_pair_id ({e}) — regenerate pairing to reset"))?;
    let psk_bytes = b64
        .decode(psk_b64)
        .map_err(|e| format!("secrets file has an invalid relay_psk ({e}) — regenerate pairing to reset"))?;
    let pair_id: [u8; 16] = pair_id_bytes
        .try_into()
        .map_err(|_| "secrets file's relay_pair_id must decode to 16 bytes".to_string())?;
    let psk: [u8; 32] = psk_bytes
        .try_into()
        .map_err(|_| "secrets file's relay_psk must decode to 32 bytes".to_string())?;
    Ok((pair_id, psk))
}

/// Load the relay pairing material, generating and persisting a fresh
/// pair_id+PSK on first use (mirrors `get_or_create_bearer_token`).
pub fn get_or_create_pairing(app: &AppHandle<Wry>) -> Result<([u8; 16], [u8; 32]), String> {
    let mut secrets = load(app)?;
    if secrets.relay_pair_id.is_empty() || secrets.relay_psk.is_empty() {
        let pair_id = generate_bytes::<16>();
        let psk = generate_bytes::<32>();
        let (pair_id_b64, psk_b64) = encode_pairing(pair_id, psk);
        secrets.relay_pair_id = pair_id_b64;
        secrets.relay_psk = psk_b64;
        store(app, &secrets)?;
        return Ok((pair_id, psk));
    }
    decode_pairing(&secrets.relay_pair_id, &secrets.relay_psk)
}

/// Replace the pairing material with a fresh pair_id+PSK and persist it —
/// every device paired with the old code loses access immediately (the
/// relay only recognizes the new pair_id once amallo reconnects with it).
pub fn regenerate_pairing(app: &AppHandle<Wry>) -> Result<([u8; 16], [u8; 32]), String> {
    let mut secrets = load(app)?;
    let pair_id = generate_bytes::<16>();
    let psk = generate_bytes::<32>();
    let (pair_id_b64, psk_b64) = encode_pairing(pair_id, psk);
    secrets.relay_pair_id = pair_id_b64;
    secrets.relay_psk = psk_b64;
    store(app, &secrets)?;
    Ok((pair_id, psk))
}
