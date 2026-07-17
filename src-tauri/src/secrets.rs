use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Wry};

/// Secrets are kept in a single JSON file in amallo's data dir, locked to the
/// current user with `0600` permissions (the same approach ngrok, the AWS CLI
/// and Docker use for their tokens). Not encrypted at rest — see the README.
#[derive(Default, Serialize, Deserialize)]
struct SecretFile {
    #[serde(default)]
    ngrok_authtoken: Option<String>,
    #[serde(default)]
    bearer_token: String,
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

pub fn get_ngrok_token(app: &AppHandle<Wry>) -> Result<Option<String>, String> {
    Ok(load(app)?.ngrok_authtoken.filter(|t| !t.is_empty()))
}

pub fn set_ngrok_token(app: &AppHandle<Wry>, token: &str) -> Result<(), String> {
    let mut secrets = load(app)?;
    secrets.ngrok_authtoken = (!token.is_empty()).then(|| token.to_string());
    store(app, &secrets)
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
