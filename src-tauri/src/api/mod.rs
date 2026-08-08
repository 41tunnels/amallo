//! HTTP surface(s) that extend the plain Ollama proxy. Named `extended`
//! rather than `amallo`: this is additional API surface layered onto the
//! Ollama-compatible proxy `proxy.rs` otherwise forwards verbatim, and the
//! name says so without binding the protocol to the product.
pub mod v1;
