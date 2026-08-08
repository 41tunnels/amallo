//! SHA-256 helpers, via aws-lc-rs — already in the dependency tree as the
//! relay E2E handshake's crypto backend (`relay/crypto.rs`), so this adds
//! no new dependency.
//!
//! The document hash is computed over raw bytes, not a canonical
//! structural form: the client hashes the exact JSON text it sends, and
//! the server hashes the exact bytes it received. There is deliberately
//! no canonical-JSON module on either side — see `records::expected_hash`
//! for the tombstone convention this implies.

use aws_lc_rs::digest;

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 of the empty byte string. This is the fixed hash convention for
/// tombstones (which carry no `data`), so that repeated deletes of the same
/// key are idempotent (`Duplicate`, not a fresh `Applied`) and so a
/// tombstone's hash is deterministic across every device without either
/// side needing to invent one.
pub const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_matches_known_constant() {
        assert_eq!(sha256_hex(b""), EMPTY_HASH);
    }

    #[test]
    fn hex_is_lowercase_and_64_chars() {
        let h = sha256_hex(b"hello world");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    }

    #[test]
    fn deterministic() {
        assert_eq!(sha256_hex(b"same"), sha256_hex(b"same"));
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }
}
