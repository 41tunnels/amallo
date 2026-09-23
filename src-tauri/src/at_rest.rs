//! At-rest encryption for synced client data (chats, characters, personas
//! and their blobs).
//!
//! The goal is that nothing a client syncs sits on disk as plaintext:
//! Spotlight, Windows Search, `grep` or a casual look inside the app data
//! folder should find only ciphertext. It is not a defence against malware
//! running as the same user - the key lives in `secrets.json` next to the
//! data (see `secrets::get_or_create_storage_key`), exactly like the
//! bearer token already does.
//!
//! Cipher: AES-256-GCM with a random 96-bit nonce per seal, via the same
//! aws-lc-rs the relay session already uses. Every seal carries caller
//! supplied associated data (the record's namespace/key, the blob's hash,
//! the collection name) so ciphertext cannot be swapped between slots
//! without failing authentication.

use aws_lc_rs::aead;
use base64::Engine;
use rand::RngCore;

/// Prefix of a sealed binary payload (blobs, legacy sync files). Eight
/// bytes that no JSON document and no common image format starts with,
/// which is what lets a store tell a pre-encryption plaintext file apart
/// from a sealed one while migrating.
const MAGIC: &[u8; 8] = b"AMLOENC1";

/// Prefix of a sealed text payload (SQLite `records.data`). A JSON value
/// can never start with `e`, so a legacy plaintext row is unambiguous.
const TEXT_PREFIX: &str = "enc1:";

const NONCE_LEN: usize = aead::NONCE_LEN;

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError;

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("could not decrypt stored data (wrong key or corrupt file)")
    }
}
impl std::error::Error for OpenError {}

pub struct AtRestKey(aead::LessSafeKey);

impl AtRestKey {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key).expect("AES-256-GCM accepts a 32-byte key");
        Self(aead::LessSafeKey::new(unbound))
    }

    /// A throwaway key, for in-memory stores and tests.
    pub fn random() -> Self {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        Self::new(&key)
    }

    /// `nonce || ciphertext || tag`, without any framing.
    fn seal_raw(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + aead::AES_256_GCM.tag_len());
        out.extend_from_slice(&nonce_bytes);
        let mut in_out = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut in_out)
            .expect("AES-GCM seal only fails on inputs far larger than anything stored here");
        out.extend_from_slice(&in_out);
        out
    }

    fn open_raw(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        if sealed.len() < NONCE_LEN + aead::AES_256_GCM.tag_len() {
            return Err(OpenError);
        }
        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| OpenError)?;
        let mut buf = ct.to_vec();
        let plain_len = self
            .0
            .open_in_place(nonce, aead::Aad::from(aad), &mut buf)
            .map_err(|_| OpenError)?
            .len();
        buf.truncate(plain_len);
        Ok(buf)
    }

    /// Seals bytes for a file on disk: `MAGIC || nonce || ciphertext || tag`.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.seal_raw(aad, plaintext));
        out
    }

    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        match sealed.strip_prefix(MAGIC.as_slice()) {
            Some(body) => self.open_raw(aad, body),
            None => Err(OpenError),
        }
    }

    /// Seals text for a TEXT column: `enc1:` + base64url(nonce || ct || tag).
    pub fn seal_text(&self, aad: &[u8], plaintext: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!("{TEXT_PREFIX}{}", b64.encode(self.seal_raw(aad, plaintext.as_bytes())))
    }

    pub fn open_text(&self, aad: &[u8], sealed: &str) -> Result<String, OpenError> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let body = sealed.strip_prefix(TEXT_PREFIX).ok_or(OpenError)?;
        let raw = b64.decode(body).map_err(|_| OpenError)?;
        String::from_utf8(self.open_raw(aad, &raw)?).map_err(|_| OpenError)
    }
}

/// Whether `bytes` were produced by [`AtRestKey::seal`] (as opposed to a
/// file written before encryption existed).
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Whether `text` was produced by [`AtRestKey::seal_text`].
pub fn is_sealed_text(text: &str) -> bool {
    text.starts_with(TEXT_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_hide_the_plaintext() {
        let k = AtRestKey::random();
        let sealed = k.seal(b"aad", b"my secret chat");
        assert!(is_sealed(&sealed));
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(k.open(b"aad", &sealed).unwrap(), b"my secret chat");
    }

    #[test]
    fn text_round_trip() {
        let k = AtRestKey::random();
        let sealed = k.seal_text(b"chats\0a", r#"{"msg":"hello"}"#);
        assert!(is_sealed_text(&sealed));
        assert!(!sealed.contains("hello"));
        assert_eq!(k.open_text(b"chats\0a", &sealed).unwrap(), r#"{"msg":"hello"}"#);
    }

    #[test]
    fn wrong_aad_or_key_fails() {
        let k = AtRestKey::random();
        let sealed = k.seal_text(b"chats\0a", "{}");
        assert_eq!(k.open_text(b"chats\0b", &sealed), Err(OpenError));
        assert_eq!(AtRestKey::random().open_text(b"chats\0a", &sealed), Err(OpenError));
        assert_eq!(AtRestKey::random().open(b"x", &k.seal(b"x", b"y")), Err(OpenError));
    }

    #[test]
    fn nonces_differ_per_seal() {
        let k = AtRestKey::random();
        assert_ne!(k.seal_text(b"", "same"), k.seal_text(b"", "same"));
    }

    #[test]
    fn plaintext_json_is_never_mistaken_for_sealed() {
        for s in [r#"{"a":1}"#, "[]", "\"enc1:\"", " {}", "1", "true", "null"] {
            assert!(!is_sealed_text(s));
            assert!(!is_sealed(s.as_bytes()));
        }
    }
}
