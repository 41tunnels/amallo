//! Namespace/key/hash charset rules.
//!
//! The old `sync.rs` allowlist (`COLLECTIONS: &[&str]`) doubled as the
//! path-traversal defense, because `collection_path()` built a filename
//! straight from the URL segment. With SQLite there is no filename, so
//! this becomes plain input validation instead — but it must stay strict,
//! because `relay/policy.rs` uses `valid_hash` for the one value in the
//! whole v1 surface that DOES become a filesystem path component (the
//! blob store's fanout directories).

/// `^[a-z][a-z0-9_]{0,31}$` — 1..=32 bytes, lowercase ASCII start. No dots,
/// dashes, slashes or percent signs: nothing here can ever form a path
/// segment, a SQL identifier, or a percent-escape, regardless of where it
/// later gets interpolated.
pub fn valid_namespace(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// 1..=128 bytes of `[A-Za-z0-9._:-]`. UUIDs today; the extra characters
/// leave room for composite keys without ever admitting a separator.
pub fn valid_key(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=128).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b':'))
}

/// Exactly 64 lowercase hex digits (a SHA-256 digest). The only value that
/// ever becomes a filesystem path component in the blob store, and it
/// cannot contain `.`, `/`, `\` or a drive letter by construction.
pub fn valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_rules() {
        assert!(valid_namespace("characters"));
        assert!(valid_namespace("a"));
        assert!(valid_namespace("a_b_9"));
        assert!(valid_namespace(&"a".repeat(32)));
        assert!(!valid_namespace(&"a".repeat(33)));
        assert!(!valid_namespace(""));
        assert!(!valid_namespace("Characters")); // uppercase
        assert!(!valid_namespace("9chars")); // must start lowercase-alpha
        assert!(!valid_namespace("chars.ns")); // dot
        assert!(!valid_namespace("chars/ns")); // slash
        assert!(!valid_namespace("../etc")); // traversal
        assert!(!valid_namespace("chars ns")); // space
    }

    #[test]
    fn key_rules() {
        assert!(valid_key("550e8400-e29b-41d4-a716-446655440000"));
        assert!(valid_key("a"));
        assert!(valid_key(&"a".repeat(128)));
        assert!(!valid_key(&"a".repeat(129)));
        assert!(!valid_key(""));
        assert!(!valid_key("a/b"));
        assert!(!valid_key("a b"));
        assert!(!valid_key("../../etc/passwd"));
    }

    #[test]
    fn hash_rules() {
        let good = "a".repeat(64);
        assert!(valid_hash(&good));
        assert!(!valid_hash(&"a".repeat(63)));
        assert!(!valid_hash(&"a".repeat(65)));
        assert!(!valid_hash(&"A".repeat(64))); // uppercase hex rejected
        assert!(!valid_hash(&"g".repeat(64))); // out-of-range hex char
        assert!(!valid_hash("../../../../etc/passwd000000000000000000000000000000")); // wrong length + bad chars
    }
}
