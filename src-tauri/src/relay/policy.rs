//! The compensating control for tunnelling arbitrary HTTP over the relay
//! (see the build plan's Step 4 rationale). Over the relay path, amallo
//! stamps its own bearer token onto every dispatched request — the PSK
//! handshake (Step 5) is what actually authenticates the peer — so
//! `require_bearer` in `proxy.rs` is a no-op for relay-originated
//! requests. This module is what keeps `/api/create`, `/api/push`, and
//! `/api/blobs/*` off the internet: only an explicit allowlist of
//! method+path pairs may reach the router at all.

use std::fmt;

const MAX_PATH_BYTES: usize = 512;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    PathTooLong,
    PathTraversal,
    NotAllowed,
    TooManyHeaders,
    HeadersTooLarge,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PolicyError::PathTooLong => "path exceeds the maximum allowed length",
            PolicyError::PathTraversal => "path contains a traversal sequence",
            PolicyError::NotAllowed => "method/path is not on the relay allowlist",
            PolicyError::TooManyHeaders => "too many headers",
            PolicyError::HeadersTooLarge => "headers exceed the maximum allowed size",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PolicyError {}

/// Exact method+path pairs the relay path may reach. Deliberately a small,
/// explicit list rather than a pattern match against Ollama's full API —
/// every entry here is something `web`'s `ollama.ts` actually calls (see
/// the build plan's integration-seam notes). Anything not listed here
/// (`/api/create`, `/api/push`, `/api/copy`, `/api/blobs/*`, ...) is
/// reachable on the LAN/direct listener, guarded by the bearer token, but
/// never over the relay.
const ALLOWED_EXACT: &[(&str, &str)] = &[
    ("GET", "/api/tags"),
    ("GET", "/api/ps"),
    ("POST", "/api/show"),
    ("POST", "/api/chat"),
    ("POST", "/api/generate"),
    ("POST", "/api/embed"),
    ("POST", "/api/pull"),
    ("DELETE", "/api/delete"),
];

/// The three sync collections `sync.rs` actually serves — see
/// `sync.rs`'s own `COLLECTIONS` allowlist, which this must stay in sync
/// with (duplicated rather than imported so a change to one doesn't
/// silently loosen the other; a mismatch fails closed either way, since
/// `sync_get`/`sync_post` re-validate the collection name themselves).
const SYNC_COLLECTIONS: &[&str] = &["characters", "personas", "chats"];

/// Validates a relay-originated request's method and path (query string
/// already stripped by the caller, but this defends against a caller that
/// forgot to). Every check runs regardless of which one fails first — the
/// order below is cheapest-first, not importance-first.
pub fn check_method_path(method: &str, path: &str) -> Result<(), PolicyError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(PolicyError::PathTooLong);
    }
    let path_only = path.split('?').next().unwrap_or(path);
    if !path_only.starts_with('/') {
        return Err(PolicyError::NotAllowed);
    }
    let lower = path_only.to_ascii_lowercase();
    if path_only.contains("..") || lower.contains("%2e") {
        return Err(PolicyError::PathTraversal);
    }

    for (m, p) in ALLOWED_EXACT {
        if method.eq_ignore_ascii_case(m) && path_only == *p {
            return Ok(());
        }
    }

    if let Some(collection) = path_only.strip_prefix("/amallo/sync/") {
        let is_get_or_post = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST");
        if is_get_or_post && !collection.contains('/') && SYNC_COLLECTIONS.contains(&collection) {
            return Ok(());
        }
    }

    Err(PolicyError::NotAllowed)
}

/// Header allowlist for relay-originated requests — stricter than the
/// local proxy's strip-list (`proxy.rs`'s `SKIP_REQUEST_HEADERS`), because
/// here amallo controls both ends of the handshake: nothing legitimate a
/// relay client needs to send should be outside content negotiation.
/// `Authorization` in particular is never let through — amallo stamps its
/// own bearer token in `dispatch.rs` regardless of what arrives here.
const ALLOWED_REQUEST_HEADERS: &[&str] = &["content-type", "accept"];

/// Filters an inbound header list down to the allowlist, after checking
/// overall count/size bounds. Returns only the headers that passed;
/// silently dropping a header is intentional here (unlike a hard failure
/// for method/path) — an extra header a client sent is not itself a
/// meaningful protocol violation, dropping it is enough.
pub fn filter_request_headers(headers: &[(String, String)]) -> Result<Vec<(String, String)>, PolicyError> {
    if headers.len() > MAX_HEADERS {
        return Err(PolicyError::TooManyHeaders);
    }
    let total: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total > MAX_HEADER_BYTES {
        return Err(PolicyError::HeadersTooLarge);
    }
    Ok(headers
        .iter()
        .filter(|(k, _)| ALLOWED_REQUEST_HEADERS.contains(&k.to_ascii_lowercase().as_str()))
        .cloned()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_known_ollama_endpoints() {
        assert!(check_method_path("GET", "/api/tags").is_ok());
        assert!(check_method_path("get", "/api/tags").is_ok(), "method match is case-insensitive");
        assert!(check_method_path("POST", "/api/chat").is_ok());
        assert!(check_method_path("POST", "/api/generate").is_ok());
        assert!(check_method_path("DELETE", "/api/delete").is_ok());
    }

    #[test]
    fn allows_sync_collections() {
        assert!(check_method_path("GET", "/amallo/sync/characters").is_ok());
        assert!(check_method_path("POST", "/amallo/sync/personas").is_ok());
        assert!(check_method_path("POST", "/amallo/sync/chats").is_ok());
    }

    #[test]
    fn rejects_unlisted_endpoints() {
        assert_eq!(
            check_method_path("POST", "/api/create"),
            Err(PolicyError::NotAllowed)
        );
        assert_eq!(
            check_method_path("POST", "/api/push"),
            Err(PolicyError::NotAllowed)
        );
        assert_eq!(
            check_method_path("GET", "/api/blobs/sha256:abc"),
            Err(PolicyError::NotAllowed)
        );
    }

    #[test]
    fn rejects_unknown_sync_collection() {
        assert_eq!(
            check_method_path("GET", "/amallo/sync/other"),
            Err(PolicyError::NotAllowed)
        );
        assert_eq!(
            check_method_path("DELETE", "/amallo/sync/chats"),
            Err(PolicyError::NotAllowed),
            "sync only allows GET/POST"
        );
    }

    #[test]
    fn rejects_path_traversal() {
        assert_eq!(
            check_method_path("GET", "/api/../secrets"),
            Err(PolicyError::PathTraversal)
        );
        assert_eq!(
            check_method_path("GET", "/api%2e%2e/secrets"),
            Err(PolicyError::PathTraversal)
        );
    }

    #[test]
    fn rejects_oversize_path() {
        let long = format!("/api/tags{}", "a".repeat(600));
        assert_eq!(check_method_path("GET", &long), Err(PolicyError::PathTooLong));
    }

    #[test]
    fn query_string_does_not_bypass_allowlist() {
        assert!(check_method_path("GET", "/api/tags?foo=bar").is_ok());
        assert_eq!(
            check_method_path("POST", "/api/create?x=1"),
            Err(PolicyError::NotAllowed)
        );
    }

    #[test]
    fn filters_headers_to_allowlist() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer stolen".to_string()),
            ("X-Forwarded-For".to_string(), "1.2.3.4".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];
        let filtered = filter_request_headers(&headers).unwrap();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|(k, _)| k == "content-type"));
        assert!(filtered.iter().any(|(k, _)| k == "Accept"));
        assert!(!filtered.iter().any(|(k, _)| k.eq_ignore_ascii_case("authorization")));
    }

    #[test]
    fn rejects_too_many_headers() {
        let headers: Vec<(String, String)> = (0..40)
            .map(|i| (format!("x-{i}"), "v".to_string()))
            .collect();
        assert_eq!(
            filter_request_headers(&headers),
            Err(PolicyError::TooManyHeaders)
        );
    }
}
