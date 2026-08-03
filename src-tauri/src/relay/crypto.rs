//! OpenCharUI relay E2E handshake and AEAD session (spec/PROTOCOL.md
//! §4-§6), implemented over `aws-lc-rs` — already in the dependency tree
//! as rustls's installed crypto provider (see `lib.rs`), so this adds no
//! new crypto stack. Mirrors the Go reference implementation in
//! `relay/internal/proto` and the TypeScript port in
//! `web/src/browser/relay/crypto.ts` byte for byte — all three are
//! checked against the same shared vectors (`tests/vectors/`). The relay
//! itself never calls this module — channel 0x01/0x02 payloads are
//! opaque to it.
//!
//! Curve: P-256, not X25519 (the web client's WebCrypto support for it is
//! too new for a phone-first app). Cipher: AES-256-GCM.

use std::fmt;

use aws_lc_rs::{aead, agreement, constant_time, digest, hkdf, hmac};

pub const ROLE_AGENT: u8 = 0x01;
pub const ROLE_CLIENT: u8 = 0x02;

const PROTO_VERSION: u8 = 0x01;

const PAIR_ID_LEN: usize = 16;
const PSK_LEN: usize = 32;
const EPK_LEN: usize = 65; // uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32)
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
const TAG_LEN: usize = 32;
const HELLO_LEN: usize = 1 + 1 + PAIR_ID_LEN + EPK_LEN + NONCE_LEN + MAC_LEN; // 147
const CONFIRM_LEN: usize = 1 + 1 + TAG_LEN; // 34

const NONCE_PREFIX_LEN: usize = 4;
const NONCE_COUNTER_LEN: usize = 8;
const GCM_NONCE_LEN: usize = NONCE_PREFIX_LEN + NONCE_COUNTER_LEN;
const GCM_TAG_LEN: usize = 16;
const DIRECTION_KEY_LEN: usize = 32; // AES-256

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    BadLength,
    BadMac,
    PairMismatch,
    RoleReflection,
    BadVersion,
    BadPoint,
    ConfirmMismatch,
    ConfirmRole,
    CounterMismatch,
    CounterExhausted,
    AuthFailed,
    /// An aws-lc-rs operation failed for a reason this module doesn't
    /// otherwise distinguish (e.g. a malformed AES key length that
    /// `UnboundKey::new` itself rejects) — not exercised by any spec
    /// vector, but every fallible aws-lc-rs call must map to *something*.
    Internal,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(error_code(*self))
    }
}

impl std::error::Error for CryptoError {}

/// Maps a [`CryptoError`] to the stable string used in the shared test
/// vectors' `expect_error` field — the same rationale as `wire.rs`'s
/// `error_code`: plain strings are what all three languages can compare,
/// error-type identity is not.
pub fn error_code(err: CryptoError) -> &'static str {
    match err {
        CryptoError::BadLength => "bad_length",
        CryptoError::BadMac => "bad_mac",
        CryptoError::PairMismatch => "pair_mismatch",
        CryptoError::RoleReflection => "role_reflection",
        CryptoError::BadVersion => "bad_version",
        CryptoError::BadPoint => "bad_point",
        CryptoError::ConfirmMismatch => "confirm_mismatch",
        CryptoError::ConfirmRole => "confirm_role",
        CryptoError::CounterMismatch => "counter_mismatch",
        CryptoError::CounterExhausted => "counter_exhausted",
        CryptoError::AuthFailed => "auth_failed",
        CryptoError::Internal => "internal",
    }
}

// --- HKDF (RFC 5869) helpers -------------------------------------------
//
// Thin wrappers around aws-lc-rs's split Extract/Expand API, mirroring
// the Go reference implementation's own hkdfExtract/hkdfExpand helpers —
// deliberately not combined into one call, so DeriveSession can extract
// the PRK exactly once and reuse it for every subsequent Expand
// (including the CONFIRM tags), matching Go byte for byte.

struct HkdfLen(usize);
impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> hkdf::Prk {
    let salt = if salt.is_empty() {
        hkdf::Salt::none(hkdf::HKDF_SHA256)
    } else {
        hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
    };
    salt.extract(ikm)
}

fn hkdf_expand(prk: &hkdf::Prk, info: &[u8], len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    prk.expand(&[info], HkdfLen(len))
        .map_err(|_| CryptoError::Internal)?
        .fill(&mut out)
        .map_err(|_| CryptoError::Internal)?;
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data).as_ref().to_vec()
}

/// Derives the HELLO-MAC key from the PSK (spec §4.3). Exported (like the
/// Go `KMac`) purely so cross-implementation debugging and vector
/// generation can inspect intermediate values — normal handshake code
/// never calls this directly except via `build_hello`/`verify_hello`.
pub fn k_mac(psk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if psk.len() != PSK_LEN {
        return Err(CryptoError::BadLength);
    }
    let prk = hkdf_extract(&[], psk);
    hkdf_expand(&prk, b"opencharui/v1 hello-mac", 32)
}

pub fn psk_ikm(psk: &[u8], transcript: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if psk.len() != PSK_LEN {
        return Err(CryptoError::BadLength);
    }
    let prk = hkdf_extract(&[], psk);
    let mut info = Vec::with_capacity(21 + 32);
    info.extend_from_slice(b"opencharui/v1 psk-ikm");
    info.extend_from_slice(transcript);
    hkdf_expand(&prk, &info, 32)
}

// --- Ephemeral P-256 keys -----------------------------------------------

/// One P-256 ECDH key pair, used for exactly one handshake and never
/// persisted or reused across reconnects (spec §4.2).
pub struct Ephemeral {
    priv_key: agreement::PrivateKey,
    pub_key_bytes: [u8; EPK_LEN],
}

impl Ephemeral {
    /// Generates a fresh, random ephemeral key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let priv_key =
            agreement::PrivateKey::generate(&agreement::ECDH_P256).map_err(|_| CryptoError::Internal)?;
        Self::from_private(priv_key)
    }

    /// Constructs a deterministic key pair from a raw 32-byte big-endian
    /// P-256 scalar. This exists solely so test vectors can make the
    /// handshake a pure function: the vector supplies the "random" input
    /// instead of the implementation generating it — see the Go
    /// `EphemeralFromScalar` and the build plan's note that every
    /// implementation of this spec must expose this seam from the start.
    pub fn from_scalar(scalar: &[u8]) -> Result<Self, CryptoError> {
        let priv_key = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, scalar)
            .map_err(|_| CryptoError::BadPoint)?;
        Self::from_private(priv_key)
    }

    fn from_private(priv_key: agreement::PrivateKey) -> Result<Self, CryptoError> {
        let pub_key = priv_key
            .compute_public_key()
            .map_err(|_| CryptoError::Internal)?;
        let bytes = pub_key.as_ref();
        if bytes.len() != EPK_LEN {
            return Err(CryptoError::Internal);
        }
        let mut pub_key_bytes = [0u8; EPK_LEN];
        pub_key_bytes.copy_from_slice(bytes);
        Ok(Self {
            priv_key,
            pub_key_bytes,
        })
    }

    /// The uncompressed SEC1 encoding (65 bytes) used as `epk` in HELLO.
    pub fn public_key_bytes(&self) -> &[u8; EPK_LEN] {
        &self.pub_key_bytes
    }

    /// Performs the key agreement against a peer's HELLO-carried public
    /// key and returns the shared X-coordinate (spec §4.4's `ecdh_x`).
    /// `peer_epk` is the raw 65-byte uncompressed point from the peer's
    /// HELLO; `CryptoError::BadPoint` if it is not a valid point on
    /// P-256 — this is also where invalid-curve attacks are rejected,
    /// as part of `agree`'s own parsing/validation.
    pub fn ecdh(&self, peer_epk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        agreement::agree(
            &self.priv_key,
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_epk),
            CryptoError::BadPoint,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
    }
}

fn validate_p256_point(bytes: &[u8]) -> Result<(), CryptoError> {
    agreement::ParsedPublicKey::try_from(agreement::UnparsedPublicKey::new(
        &agreement::ECDH_P256,
        bytes,
    ))
    .map(|_| ())
    .map_err(|_| CryptoError::BadPoint)
}

// --- HELLO ---------------------------------------------------------------

/// A parsed, not-yet-verified HELLO.
pub struct HelloFields {
    pub ver: u8,
    pub role: u8,
    pub pair_id: [u8; PAIR_ID_LEN],
    pub epk: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub mac: Vec<u8>,
    /// The exact 147-byte HELLO wire encoding, needed verbatim for the
    /// transcript.
    pub raw: Vec<u8>,
}

/// Encodes and MACs a HELLO message (spec §4.3). `nonce` must be exactly
/// 32 bytes — callers pass a fresh random nonce in production and a
/// vector-fixed nonce when validating against test vectors.
pub fn build_hello(
    psk: &[u8],
    role: u8,
    pair_id: [u8; PAIR_ID_LEN],
    epk: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    if epk.len() != EPK_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut body = Vec::with_capacity(HELLO_LEN - MAC_LEN);
    body.push(PROTO_VERSION);
    body.push(role);
    body.extend_from_slice(&pair_id);
    body.extend_from_slice(epk);
    body.extend_from_slice(&nonce);

    let kmac = k_mac(psk)?;
    let mut mac_input = Vec::with_capacity(20 + body.len());
    mac_input.extend_from_slice(b"opencharui/v1 hello");
    mac_input.extend_from_slice(&body);
    let mac = hmac_sha256(&kmac, &mac_input);

    let mut out = body;
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Splits a raw HELLO without verifying it — use [`verify_hello`] for the
/// authenticated path. Exposed separately because negative test vectors
/// need to observe "parses fine, fails verification" distinctly.
pub fn parse_hello(raw: &[u8]) -> Result<HelloFields, CryptoError> {
    if raw.len() != HELLO_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut off = 0;
    let ver = raw[off];
    off += 1;
    let role = raw[off];
    off += 1;
    let mut pair_id = [0u8; PAIR_ID_LEN];
    pair_id.copy_from_slice(&raw[off..off + PAIR_ID_LEN]);
    off += PAIR_ID_LEN;
    let epk = raw[off..off + EPK_LEN].to_vec();
    off += EPK_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[off..off + NONCE_LEN]);
    off += NONCE_LEN;
    let mac = raw[off..off + MAC_LEN].to_vec();
    Ok(HelloFields {
        ver,
        role,
        pair_id,
        epk,
        nonce,
        mac,
        raw: raw.to_vec(),
    })
}

/// Parses and applies every check from spec §4.3, in the same order as
/// the Go reference implementation (version, pair_id, role, MAC, point) —
/// negative test vectors encode whichever error that specific ordering
/// produces first, so this order is load-bearing for vector agreement,
/// not arbitrary. `own_role` is the verifier's own role: a peer's HELLO
/// must always carry the *other* role, or it's a reflection of our own.
pub fn verify_hello(
    psk: &[u8],
    raw: &[u8],
    expect_pair_id: [u8; PAIR_ID_LEN],
    own_role: u8,
) -> Result<HelloFields, CryptoError> {
    let f = parse_hello(raw)?;
    if f.ver != PROTO_VERSION {
        return Err(CryptoError::BadVersion);
    }
    if f.pair_id != expect_pair_id {
        return Err(CryptoError::PairMismatch);
    }
    if f.role == own_role {
        return Err(CryptoError::RoleReflection);
    }

    let kmac = k_mac(psk)?;
    let mut mac_input = Vec::with_capacity(20 + HELLO_LEN - MAC_LEN);
    mac_input.extend_from_slice(b"opencharui/v1 hello");
    mac_input.extend_from_slice(&raw[..HELLO_LEN - MAC_LEN]);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &kmac);
    if hmac::verify(&key, &mac_input, &f.mac).is_err() {
        return Err(CryptoError::BadMac);
    }

    validate_p256_point(&f.epk)?;

    Ok(f)
}

// --- Transcript and session key derivation --------------------------------

/// Computes spec §4.4's canonical, role-ordered transcript hash.
/// `hello_agent`/`hello_web` are the exact 147-byte HELLO wire encodings
/// — agent's HELLO always precedes web's in the hash input, regardless of
/// which one either side observed first.
pub fn transcript(hello_agent: &[u8], hello_web: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"opencharui/v1 transcript");
    ctx.update(hello_agent);
    ctx.update(hello_web);
    let d = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Everything derived from one handshake (spec §4.4). `prk` is kept only
/// to derive CONFIRM tags — it is aws-lc-rs's opaque `Prk` type rather
/// than raw bytes, exactly the same constraint the WebCrypto
/// implementation has with its non-extractable `ikmKey`: this type has
/// no "give me the raw PRK" escape hatch, so every subsequent
/// Expand-shaped derivation (the CONFIRM tags) goes back through it
/// rather than through a materialized byte string.
pub struct SessionKeys {
    prk: hkdf::Prk,
    pub k_a2w: Vec<u8>,
    pub k_w2a: Vec<u8>,
    pub np_a2w: Vec<u8>,
    pub np_w2a: Vec<u8>,
}

/// Computes the session keys from the PSK, the transcript, and the raw
/// ECDH shared secret (spec §4.4). `psk_ikm` folded into the extraction
/// IKM is what blocks relay MITM: a relay without the PSK — even one that
/// swapped both ephemeral public keys in transit — cannot derive
/// anything past this point.
pub fn derive_session(psk: &[u8], transcript: &[u8; 32], ecdh_x: &[u8]) -> Result<SessionKeys, CryptoError> {
    let pi = psk_ikm(psk, transcript)?;
    let mut ikm = Vec::with_capacity(ecdh_x.len() + pi.len());
    ikm.extend_from_slice(ecdh_x);
    ikm.extend_from_slice(&pi);

    let prk = hkdf_extract(transcript, &ikm);
    let k_a2w = hkdf_expand(&prk, b"opencharui/v1 key-a2w", 32)?;
    let k_w2a = hkdf_expand(&prk, b"opencharui/v1 key-w2a", 32)?;
    let np_a2w = hkdf_expand(&prk, b"opencharui/v1 np-a2w", 4)?;
    let np_w2a = hkdf_expand(&prk, b"opencharui/v1 np-w2a", 4)?;

    Ok(SessionKeys {
        prk,
        k_a2w,
        k_w2a,
        np_a2w,
        np_w2a,
    })
}

// --- CONFIRM ---------------------------------------------------------------

fn confirm_tag(session: &SessionKeys, role: u8) -> Result<Vec<u8>, CryptoError> {
    let label: &[u8] = if role == ROLE_CLIENT {
        b"opencharui/v1 confirm-web"
    } else {
        b"opencharui/v1 confirm-agent"
    };
    hkdf_expand(&session.prk, label, TAG_LEN)
}

/// Encodes this side's CONFIRM (spec §4.5). `role` is the sender's own
/// role.
pub fn build_confirm(session: &SessionKeys, role: u8) -> Result<Vec<u8>, CryptoError> {
    let tag = confirm_tag(session, role)?;
    let mut out = Vec::with_capacity(CONFIRM_LEN);
    out.push(PROTO_VERSION);
    out.push(role);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Checks a peer's CONFIRM. `expect_role` is the *peer's* expected role
/// (the role opposite the verifier). No channel-0x01 frame may be sent or
/// accepted before this succeeds (spec §4.5) — enforced by callers, not
/// by this function.
pub fn verify_confirm(session: &SessionKeys, raw: &[u8], expect_role: u8) -> Result<(), CryptoError> {
    if raw.len() != CONFIRM_LEN {
        return Err(CryptoError::BadLength);
    }
    if raw[0] != PROTO_VERSION {
        return Err(CryptoError::BadVersion);
    }
    let role = raw[1];
    if role != expect_role {
        return Err(CryptoError::ConfirmRole);
    }
    let expected = confirm_tag(session, role)?;
    if constant_time::verify_slices_are_equal(&expected, &raw[2..2 + TAG_LEN]).is_err() {
        return Err(CryptoError::ConfirmMismatch);
    }
    Ok(())
}

// --- AEAD session (spec §5) ------------------------------------------------

fn make_aead_key(key: &[u8]) -> Result<aead::LessSafeKey, CryptoError> {
    if key.len() != DIRECTION_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| CryptoError::Internal)?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u64) -> [u8; GCM_NONCE_LEN] {
    let mut out = [0u8; GCM_NONCE_LEN];
    out[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    out[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    out
}

/// Builds `[outer_header_bytes][counter:8]` per spec §5. `header_bytes`
/// must be the exact outer-frame header bytes that accompanied this
/// payload on the wire (see `wire::OuterHeader::header_bytes`).
fn make_aad(header_bytes: &[u8], counter: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_bytes.len() + NONCE_COUNTER_LEN);
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

fn parse_prefix(prefix: &[u8]) -> Result<[u8; NONCE_PREFIX_LEN], CryptoError> {
    if prefix.len() != NONCE_PREFIX_LEN {
        return Err(CryptoError::BadLength);
    }
    let mut out = [0u8; NONCE_PREFIX_LEN];
    out.copy_from_slice(prefix);
    Ok(out)
}

/// Encrypts one direction of a session. Owns the counter exclusively.
///
/// spec §5.1 is not a suggestion: exactly one `Sealer` must exist per
/// direction, and [`Sealer::seal`] must not be called concurrently (e.g.
/// from two in-flight streams at once without external serialization).
/// Concurrent unsynchronized use produces two frames encrypted under the
/// same nonce, which breaks AES-GCM catastrophically (authentication key
/// recovery, plaintext XOR disclosure). `&mut self` on `seal` is the
/// compiler-enforced version of that rule: a `Sealer` cannot be called
/// from two tasks at once without an externally-owned `Mutex` or (the
/// intended shape per the build plan) a single writer task that owns it
/// outright, fed by an `mpsc` channel.
pub struct Sealer {
    key: aead::LessSafeKey,
    prefix: [u8; NONCE_PREFIX_LEN],
    counter: u64,
    closed: bool,
}

impl Sealer {
    pub fn new(key: &[u8], prefix: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: make_aead_key(key)?,
            prefix: parse_prefix(prefix)?,
            counter: 0,
            closed: false,
        })
    }

    /// Test/vector-generation only: starts the counter at `start` rather
    /// than 0. Normal sessions always start at 0 and never resume a
    /// counter across a reconnect (spec §5.1) — this exists only so
    /// vectors can be checked at specific counter values without a
    /// production API exposing a "set counter" foot-gun.
    pub fn new_at(key: &[u8], prefix: &[u8], start_counter: u64) -> Result<Self, CryptoError> {
        let mut s = Self::new(key, prefix)?;
        s.counter = start_counter;
        Ok(s)
    }

    /// Encrypts `plaintext` for the given outer-frame header bytes
    /// (spec §5: AAD = outer_header_bytes ‖ counter) and returns the
    /// full channel-0x01 payload: `[counter:8][ciphertext‖tag]`.
    /// Returns `CryptoError::CounterExhausted` — a hard failure, never a
    /// silent wrap — if the counter would overflow.
    pub fn seal(&mut self, header_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.closed {
            return Err(CryptoError::CounterExhausted);
        }
        let counter = self.counter;
        if counter == u64::MAX {
            self.closed = true;
            return Err(CryptoError::CounterExhausted);
        }
        let nonce_bytes = make_nonce(&self.prefix, counter);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::Internal)?;
        let aad = make_aad(header_bytes, counter);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(&aad), &mut in_out)
            .map_err(|_| CryptoError::Internal)?;

        self.counter += 1;
        let mut out = Vec::with_capacity(NONCE_COUNTER_LEN + in_out.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&in_out);
        Ok(out)
    }
}

/// Decrypts and authenticates one direction of a session. Rejects any
/// payload whose counter is not exactly the next expected value — no
/// window, no reordering (spec §5).
pub struct Opener {
    key: aead::LessSafeKey,
    prefix: [u8; NONCE_PREFIX_LEN],
    expected: u64,
    closed: bool,
}

impl Opener {
    pub fn new(key: &[u8], prefix: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: make_aead_key(key)?,
            prefix: parse_prefix(prefix)?,
            expected: 0,
            closed: false,
        })
    }

    /// Test-only: see [`Sealer::new_at`].
    pub fn new_at(key: &[u8], prefix: &[u8], start: u64) -> Result<Self, CryptoError> {
        let mut o = Self::new(key, prefix)?;
        o.expected = start;
        Ok(o)
    }

    /// Verifies and decrypts a channel-0x01 payload. `header_bytes` must
    /// be the exact outer-frame header bytes that accompanied this
    /// payload on the wire.
    pub fn open(&mut self, header_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.closed {
            return Err(CryptoError::CounterExhausted);
        }
        if payload.len() < NONCE_COUNTER_LEN + GCM_TAG_LEN {
            return Err(CryptoError::BadLength);
        }
        let counter = u64::from_be_bytes(payload[..NONCE_COUNTER_LEN].try_into().unwrap());
        if counter != self.expected {
            return Err(CryptoError::CounterMismatch);
        }
        let sealed = &payload[NONCE_COUNTER_LEN..];

        let nonce_bytes = make_nonce(&self.prefix, counter);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::Internal)?;
        let aad = make_aad(header_bytes, counter);

        let mut buf = sealed.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aead::Aad::from(&aad), &mut buf)
            .map_err(|_| CryptoError::AuthFailed)?
            .to_vec();

        if self.expected == u64::MAX {
            self.closed = true;
        } else {
            self.expected += 1;
        }
        Ok(plaintext)
    }
}

// --- Tests ---------------------------------------------------------------
//
// Validated against the shared cross-language vectors vendored from the
// relay repo (tests/vectors/, generated by `go run ./cmd/genvectors`).
// See `wire.rs`'s test module for the same rationale: if these fail after
// a genuine protocol change, regenerate and re-vendor; if they fail after
// only editing this file, this file has a bug relative to the Go
// reference implementation.

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;

    fn load_vectors<T: for<'de> Deserialize<'de>>(name: &str) -> T {
        let path = format!("tests/vectors/{name}");
        let data = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("reading {path}: {e} (vendor tests/vectors/ from the relay repo first)")
        });
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        if s.is_empty() {
            return Vec::new();
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn arr16(v: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(v);
        out
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(v);
        out
    }

    #[derive(Deserialize)]
    struct HandshakeVector {
        name: String,
        inputs: HandshakeInputs,
        expected: Option<HandshakeExpected>,
        #[serde(default)]
        expect_error: String,
        #[serde(default)]
        verify_raw_hello_hex: String,
        #[serde(default)]
        verify_own_role_hex: String,
        #[serde(default)]
        verify_pair_id_hex: String,
    }
    #[derive(Deserialize)]
    struct HandshakeInputs {
        pair_id_hex: String,
        psk_hex: String,
        agent_eph_priv_raw_hex: String,
        web_eph_priv_raw_hex: String,
        agent_nonce_hex: String,
        web_nonce_hex: String,
    }
    #[derive(Deserialize)]
    struct HandshakeExpected {
        k_mac_hex: String,
        agent_epk_hex: String,
        web_epk_hex: String,
        hello_agent_hex: String,
        hello_web_hex: String,
        transcript_hex: String,
        ecdh_x_hex: String,
        psk_ikm_hex: String,
        k_a2w_hex: String,
        k_w2a_hex: String,
        np_a2w_hex: String,
        np_w2a_hex: String,
        confirm_agent_hex: String,
        confirm_web_hex: String,
    }

    #[test]
    fn vectors_handshake() {
        let cases: Vec<HandshakeVector> = load_vectors("handshake.json");

        for c in &cases {
            let psk = hex_decode(&c.inputs.psk_hex);

            if !c.verify_raw_hello_hex.is_empty() {
                let pair_id = arr16(&hex_decode(&c.verify_pair_id_hex));
                let own_role = hex_decode(&c.verify_own_role_hex)[0];
                let raw = hex_decode(&c.verify_raw_hello_hex);
                let result = verify_hello(&psk, &raw, pair_id, own_role);
                if !c.expect_error.is_empty() {
                    let err = result.err().unwrap_or_else(|| panic!("case {}: expected an error", c.name));
                    assert_eq!(error_code(err), c.expect_error, "case {}", c.name);
                } else {
                    result.unwrap_or_else(|e| panic!("case {}: unexpected error: {e}", c.name));
                }
                continue;
            }

            let expected = c
                .expected
                .as_ref()
                .unwrap_or_else(|| panic!("case {}: missing `expected`", c.name));
            let pair_id = arr16(&hex_decode(&c.inputs.pair_id_hex));
            let agent_eph =
                Ephemeral::from_scalar(&hex_decode(&c.inputs.agent_eph_priv_raw_hex))
                    .unwrap_or_else(|e| panic!("case {}: agent ephemeral: {e}", c.name));
            let web_eph = Ephemeral::from_scalar(&hex_decode(&c.inputs.web_eph_priv_raw_hex))
                .unwrap_or_else(|e| panic!("case {}: web ephemeral: {e}", c.name));
            let agent_nonce = arr32(&hex_decode(&c.inputs.agent_nonce_hex));
            let web_nonce = arr32(&hex_decode(&c.inputs.web_nonce_hex));

            assert_eq!(hex_encode(&k_mac(&psk).unwrap()), expected.k_mac_hex, "case {} k_mac", c.name);
            assert_eq!(
                hex_encode(agent_eph.public_key_bytes()),
                expected.agent_epk_hex,
                "case {} agent_epk",
                c.name
            );
            assert_eq!(
                hex_encode(web_eph.public_key_bytes()),
                expected.web_epk_hex,
                "case {} web_epk",
                c.name
            );

            let hello_agent = build_hello(&psk, ROLE_AGENT, pair_id, agent_eph.public_key_bytes(), agent_nonce)
                .unwrap_or_else(|e| panic!("case {}: build_hello agent: {e}", c.name));
            let hello_web = build_hello(&psk, ROLE_CLIENT, pair_id, web_eph.public_key_bytes(), web_nonce)
                .unwrap_or_else(|e| panic!("case {}: build_hello web: {e}", c.name));
            assert_eq!(hex_encode(&hello_agent), expected.hello_agent_hex, "case {} hello_agent", c.name);
            assert_eq!(hex_encode(&hello_web), expected.hello_web_hex, "case {} hello_web", c.name);

            verify_hello(&psk, &hello_web, pair_id, ROLE_AGENT)
                .unwrap_or_else(|e| panic!("case {}: agent verifying web hello: {e}", c.name));
            verify_hello(&psk, &hello_agent, pair_id, ROLE_CLIENT)
                .unwrap_or_else(|e| panic!("case {}: web verifying agent hello: {e}", c.name));

            let t = transcript(&hello_agent, &hello_web);
            assert_eq!(hex_encode(&t), expected.transcript_hex, "case {} transcript", c.name);

            let ecdh_x = agent_eph
                .ecdh(web_eph.public_key_bytes())
                .unwrap_or_else(|e| panic!("case {}: ecdh: {e}", c.name));
            assert_eq!(hex_encode(&ecdh_x), expected.ecdh_x_hex, "case {} ecdh_x", c.name);

            assert_eq!(
                hex_encode(&psk_ikm(&psk, &t).unwrap()),
                expected.psk_ikm_hex,
                "case {} psk_ikm",
                c.name
            );

            let session = derive_session(&psk, &t, &ecdh_x)
                .unwrap_or_else(|e| panic!("case {}: derive_session: {e}", c.name));
            assert_eq!(hex_encode(&session.k_a2w), expected.k_a2w_hex, "case {} k_a2w", c.name);
            assert_eq!(hex_encode(&session.k_w2a), expected.k_w2a_hex, "case {} k_w2a", c.name);
            assert_eq!(hex_encode(&session.np_a2w), expected.np_a2w_hex, "case {} np_a2w", c.name);
            assert_eq!(hex_encode(&session.np_w2a), expected.np_w2a_hex, "case {} np_w2a", c.name);

            let confirm_agent = build_confirm(&session, ROLE_AGENT).unwrap();
            let confirm_web = build_confirm(&session, ROLE_CLIENT).unwrap();
            assert_eq!(hex_encode(&confirm_agent), expected.confirm_agent_hex, "case {} confirm_agent", c.name);
            assert_eq!(hex_encode(&confirm_web), expected.confirm_web_hex, "case {} confirm_web", c.name);

            verify_confirm(&session, &confirm_agent, ROLE_AGENT)
                .unwrap_or_else(|e| panic!("case {}: verifying agent confirm: {e}", c.name));
            verify_confirm(&session, &confirm_web, ROLE_CLIENT)
                .unwrap_or_else(|e| panic!("case {}: verifying web confirm: {e}", c.name));
        }
    }

    #[derive(Deserialize)]
    struct AeadVector {
        name: String,
        key_hex: String,
        prefix_hex: String,
        header_hex: String,
        counter: u64,
        #[serde(default)]
        plaintext_hex: String,
        ciphertext_payload_hex: String,
        #[serde(default)]
        expect_error: String,
    }

    #[test]
    fn vectors_aead() {
        let cases: Vec<AeadVector> = load_vectors("aead.json");

        for c in &cases {
            let key = hex_decode(&c.key_hex);
            let prefix = hex_decode(&c.prefix_hex);
            let header = hex_decode(&c.header_hex);

            if !c.expect_error.is_empty() {
                // Negative case: Open the supplied (possibly tampered,
                // possibly out-of-order) payload against a freshly-reset
                // Opener, so a "counter_gap" case is exercised on its own
                // terms rather than one advanced by unrelated prior
                // calls.
                let mut opener = Opener::new_at(&key, &prefix, 0).unwrap();
                let result = opener.open(&header, &hex_decode(&c.ciphertext_payload_hex));
                let err = result.err().unwrap_or_else(|| panic!("case {}: expected an error", c.name));
                assert_eq!(error_code(err), c.expect_error, "case {}", c.name);
                continue;
            }

            let mut sealer = Sealer::new_at(&key, &prefix, c.counter).unwrap();
            let ct = sealer
                .seal(&header, &hex_decode(&c.plaintext_hex))
                .unwrap_or_else(|e| panic!("case {}: seal: {e}", c.name));
            assert_eq!(hex_encode(&ct), c.ciphertext_payload_hex, "case {} ciphertext", c.name);

            let mut opener = Opener::new_at(&key, &prefix, c.counter).unwrap();
            let pt = opener
                .open(&header, &ct)
                .unwrap_or_else(|e| panic!("case {}: open: {e}", c.name));
            assert_eq!(hex_encode(&pt), c.plaintext_hex, "case {} plaintext", c.name);
        }
    }

    #[derive(Deserialize)]
    struct SessionVector {
        k_a2w_hex: String,
        k_w2a_hex: String,
        np_a2w_hex: String,
        np_w2a_hex: String,
        frames: Vec<SessionFrame>,
    }
    #[derive(Deserialize)]
    struct SessionFrame {
        dir: String,
        inner_hex: String,
        ciphertext_hex: String,
    }

    /// Replays a full ordered transcript (spec §5/§6's batching-agnostic
    /// happy path): agent->web frames sealed with k_a2w and opened with
    /// k_w2a by the peer, and vice versa — a golden end-to-end check that
    /// doesn't depend on the handshake having run in this process, only
    /// on the derived direction keys matching Go's.
    #[test]
    fn vectors_session() {
        let v: SessionVector = load_vectors("session.json");

        let prefix_a2w = hex_decode(&v.np_a2w_hex);
        let prefix_w2a = hex_decode(&v.np_w2a_hex);
        let k_a2w = hex_decode(&v.k_a2w_hex);
        let k_w2a = hex_decode(&v.k_w2a_hex);

        let mut sealer_a2w = Sealer::new(&k_a2w, &prefix_a2w).unwrap();
        let mut opener_a2w = Opener::new(&k_a2w, &prefix_a2w).unwrap();
        let mut sealer_w2a = Sealer::new(&k_w2a, &prefix_w2a).unwrap();
        let mut opener_w2a = Opener::new(&k_w2a, &prefix_w2a).unwrap();

        // The outer-frame header is constant (channel 0x01, no flags) for
        // every frame in this vector — see genvectors/spec §2.
        let header = [0x01u8, 0x00];

        for (i, f) in v.frames.iter().enumerate() {
            let inner = hex_decode(&f.inner_hex);
            let want_ct = hex_decode(&f.ciphertext_hex);
            match f.dir.as_str() {
                "a2w" => {
                    let ct = sealer_a2w.seal(&header, &inner).unwrap_or_else(|e| panic!("frame {i}: seal a2w: {e}"));
                    assert_eq!(hex_encode(&ct), hex_encode(&want_ct), "frame {i} ciphertext");
                    let pt = opener_a2w.open(&header, &ct).unwrap_or_else(|e| panic!("frame {i}: open a2w: {e}"));
                    assert_eq!(hex_encode(&pt), hex_encode(&inner), "frame {i} plaintext round-trip");
                }
                "w2a" => {
                    let ct = sealer_w2a.seal(&header, &inner).unwrap_or_else(|e| panic!("frame {i}: seal w2a: {e}"));
                    assert_eq!(hex_encode(&ct), hex_encode(&want_ct), "frame {i} ciphertext");
                    let pt = opener_w2a.open(&header, &ct).unwrap_or_else(|e| panic!("frame {i}: open w2a: {e}"));
                    assert_eq!(hex_encode(&pt), hex_encode(&inner), "frame {i} plaintext round-trip");
                }
                other => panic!("frame {i}: unknown dir {other:?}"),
            }
        }
    }

    #[test]
    fn sealer_opener_round_trip_independent_of_vectors() {
        let key = [7u8; 32];
        let prefix = [1u8, 2, 3, 4];
        let mut sealer = Sealer::new(&key, &prefix).unwrap();
        let mut opener = Opener::new(&key, &prefix).unwrap();
        let header = [0x01u8, 0x00];

        for i in 0..5u8 {
            let plaintext = vec![i; 10];
            let ct = sealer.seal(&header, &plaintext).unwrap();
            let pt = opener.open(&header, &ct).unwrap();
            assert_eq!(pt, plaintext);
        }
    }

    #[test]
    fn opener_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let prefix = [1u8, 2, 3, 4];
        let mut sealer = Sealer::new(&key, &prefix).unwrap();
        let mut opener = Opener::new(&key, &prefix).unwrap();
        let header = [0x01u8, 0x00];

        let mut ct = sealer.seal(&header, b"hello").unwrap();
        *ct.last_mut().unwrap() ^= 0xFF;
        assert_eq!(opener.open(&header, &ct), Err(CryptoError::AuthFailed));
    }

    #[test]
    fn opener_rejects_a_gap() {
        let key = [7u8; 32];
        let prefix = [1u8, 2, 3, 4];
        let mut sealer = Sealer::new(&key, &prefix).unwrap();
        let mut opener = Opener::new(&key, &prefix).unwrap();
        let header = [0x01u8, 0x00];

        let _first = sealer.seal(&header, b"one").unwrap();
        let second = sealer.seal(&header, b"two").unwrap();
        // Skip `_first` — the Opener still expects counter 0.
        assert_eq!(opener.open(&header, &second), Err(CryptoError::CounterMismatch));
    }
}
