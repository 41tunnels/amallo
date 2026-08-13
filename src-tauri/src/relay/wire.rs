//! OpenCharUI relay wire format: the outer frame (relay-visible) and the
//! inner frame (carried inside decrypted channel-0x01 payloads). Mirrors
//! the Go reference implementation in `relay/internal/wire` byte for
//! byte — both are checked against the same shared vectors in
//! `tests/vectors/`. See the relay repo's `spec/PROTOCOL.md` (§2, §6) for
//! the normative description; this module is a transcription of it.

use std::fmt;

/// Outer-frame channel byte (spec §2). Modeled as a thin newtype rather
/// than a closed enum: an unrecognized value is not itself a protocol
/// error (the relay forwards anything that isn't the control channel as
/// opaque data — see spec §2 and the Go `ParseOuter`), so this type must
/// not reject one either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel(pub u8);

pub const CHANNEL_CONTROL: Channel = Channel(0x00);
pub const CHANNEL_CIPHERTEXT: Channel = Channel(0x01);
pub const CHANNEL_HANDSHAKE: Channel = Channel(0x02);
/// Inner frames with no AEAD wrapping, carrying the OpenAI-compatible
/// HTTP endpoint's lane (spec §11), where the peer is the relay itself
/// acting on behalf of a third-party client that has no PSK.
///
/// Only valid on a connection whose hello asked for that lane — a
/// `mode:"dual"` one in amallo's case (spec §11.3). The read loop refuses
/// it otherwise, and it is dispatched against the inference-only
/// allowlist, never the E2E one.
pub const CHANNEL_PLAIN: Channel = Channel(0x03);

const FLAG_CONN_ID: u8 = 0x01;
/// Every reserved bit (1-7): MUST be zero in v1 (spec §2).
const FLAGS_RESERVED_MASK: u8 = 0xFE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    FrameTooShort,
    ReservedFlagsSet,
    ConnIdNotV1,
    InnerFrameTooShort,
    InnerPayloadTooLong,
    InnerTruncated,
    InnerReservedType,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            WireError::FrameTooShort => "outer frame too short",
            WireError::ReservedFlagsSet => "reserved flag bits set",
            WireError::ConnIdNotV1 => "conn_id present but not supported in v1",
            WireError::InnerFrameTooShort => "inner frame header truncated",
            WireError::InnerPayloadTooLong => "inner payload exceeds 24-bit length",
            WireError::InnerTruncated => "inner frame payload truncated",
            WireError::InnerReservedType => "reserved inner frame type used in v1",
        };
        f.write_str(s)
    }
}

impl std::error::Error for WireError {}

/// Maps a [`WireError`] to the stable string used in the shared test
/// vectors' `expect_error` field — the same rationale as the Go and
/// TypeScript implementations' equivalents: plain strings are what all
/// three languages can compare, error-type identity is not.
pub fn error_code(err: WireError) -> &'static str {
    match err {
        WireError::FrameTooShort => "frame_too_short",
        WireError::ReservedFlagsSet => "reserved_flags_set",
        WireError::ConnIdNotV1 => "conn_id_not_v1",
        WireError::InnerFrameTooShort => "inner_frame_too_short",
        WireError::InnerPayloadTooLong => "inner_payload_too_long",
        WireError::InnerTruncated => "inner_truncated",
        WireError::InnerReservedType => "inner_reserved_type",
    }
}

/// Parsed `[channel][flags]` outer-frame header, exactly as transmitted.
/// `header_bytes` is what goes into the AEAD associated data once Step 5
/// adds the AEAD layer — kept as the literal wire bytes, not a
/// re-serialization, so a serialization bug elsewhere can never silently
/// change what was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterHeader {
    pub channel: Channel,
    pub flags: u8,
    pub header_bytes: [u8; 2],
}

/// Splits a raw WebSocket binary message into its header and payload.
/// Validates the reserved-bits rule (spec §2) but does not interpret the
/// payload — that is the caller's job, based on `channel`.
pub fn parse_outer(msg: &[u8]) -> Result<(OuterHeader, &[u8]), WireError> {
    if msg.len() < 2 {
        return Err(WireError::FrameTooShort);
    }
    let flags = msg[1];
    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(WireError::ReservedFlagsSet);
    }
    if flags & FLAG_CONN_ID != 0 {
        // Defined by the spec's wire format but not a valid v1 message.
        return Err(WireError::ConnIdNotV1);
    }
    let header = OuterHeader {
        channel: Channel(msg[0]),
        flags,
        header_bytes: [msg[0], msg[1]],
    };
    Ok((header, &msg[2..]))
}

/// Builds a v1 outer frame (no `conn_id` — that field does not exist yet).
pub fn encode_outer(channel: Channel, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(channel.0);
    out.push(0);
    out.extend_from_slice(payload);
    out
}

// --- Inner frames (spec §6) -------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerType(pub u8);

pub const INNER_REQ: InnerType = InnerType(0x01);
pub const INNER_REQ_BODY: InnerType = InnerType(0x02);
pub const INNER_REQ_END: InnerType = InnerType(0x03);
pub const INNER_RESP: InnerType = InnerType(0x04);
pub const INNER_RESP_BODY: InnerType = InnerType(0x05);
pub const INNER_RESP_END: InnerType = InnerType(0x06);
pub const INNER_CANCEL: InnerType = InnerType(0x07);
pub const INNER_ERROR: InnerType = InnerType(0x08);

// Reserved — MUST NOT be sent in v1 (spec §6, §9).
pub const INNER_WINDOW_UPDATE: InnerType = InnerType(0x09);
pub const INNER_PING: InnerType = InnerType(0x0A);
pub const INNER_PONG: InnerType = InnerType(0x0B);

fn is_reserved_inner_type(t: InnerType) -> bool {
    matches!(t, INNER_WINDOW_UPDATE | INNER_PING | INNER_PONG)
}

/// Largest payload representable in the 3-byte length field (spec §6):
/// 2^24 - 1.
pub const MAX_INNER_PAYLOAD: usize = (1 << 24) - 1;

const INNER_HEADER_LEN: usize = 1 + 4 + 3; // type + stream_id + len

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerFrame {
    pub typ: InnerType,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

/// Appends the wire encoding of `frame` to `dst`, so callers can
/// concatenate multiple frames into one ciphertext payload cheaply (spec
/// §6 batching — see the design notes in the build plan).
pub fn encode_inner(dst: &mut Vec<u8>, frame: &InnerFrame) -> Result<(), WireError> {
    if frame.payload.len() > MAX_INNER_PAYLOAD {
        return Err(WireError::InnerPayloadTooLong);
    }
    if is_reserved_inner_type(frame.typ) {
        return Err(WireError::InnerReservedType);
    }
    dst.reserve(INNER_HEADER_LEN + frame.payload.len());
    dst.push(frame.typ.0);
    dst.extend_from_slice(&frame.stream_id.to_be_bytes());
    let len = frame.payload.len() as u32;
    dst.push((len >> 16) as u8);
    dst.push((len >> 8) as u8);
    dst.push(len as u8);
    dst.extend_from_slice(&frame.payload);
    Ok(())
}

/// Parses every inner frame concatenated in `buf` — a single decrypted
/// ciphertext payload may carry more than one inner frame (spec §6
/// batching), so both sides must always decode a payload as a sequence,
/// never assume exactly one frame per payload.
pub fn decode_inner_all(mut buf: &[u8]) -> Result<Vec<InnerFrame>, WireError> {
    let mut frames = Vec::new();
    while !buf.is_empty() {
        let (frame, rest) = decode_inner_one(buf)?;
        if is_reserved_inner_type(frame.typ) {
            return Err(WireError::InnerReservedType);
        }
        frames.push(frame);
        buf = rest;
    }
    Ok(frames)
}

fn decode_inner_one(buf: &[u8]) -> Result<(InnerFrame, &[u8]), WireError> {
    if buf.len() < INNER_HEADER_LEN {
        return Err(WireError::InnerFrameTooShort);
    }
    let typ = InnerType(buf[0]);
    let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let length = ((buf[5] as usize) << 16) | ((buf[6] as usize) << 8) | (buf[7] as usize);
    let rest = &buf[INNER_HEADER_LEN..];
    if rest.len() < length {
        return Err(WireError::InnerTruncated);
    }
    let payload = rest[..length].to_vec();
    Ok((
        InnerFrame {
            typ,
            stream_id,
            payload,
        },
        &rest[length..],
    ))
}

/// Reports whether `stream_id` was allocated by the web client (odd, per
/// spec §6). Agent-initiated (even) streams are reserved for a future
/// push-style extension and unused in v1.
pub fn is_client_initiated(stream_id: u32) -> bool {
    stream_id % 2 == 1
}

// --- Tests -------------------------------------------------------------
//
// Validated against the shared cross-language vectors vendored from the
// relay repo (tests/vectors/, generated by `go run ./cmd/genvectors` — see
// that repo's spec/PROTOCOL.md). If these fail after a genuine protocol
// change, regenerate and re-vendor; if they fail after only editing this
// file, this file has a bug relative to the Go reference implementation.

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

    #[derive(Deserialize)]
    struct FrameOuterVectors {
        encode: Vec<FrameOuterEncodeCase>,
        parse: Vec<FrameOuterParseCase>,
    }
    #[derive(Deserialize)]
    struct FrameOuterEncodeCase {
        name: String,
        channel_hex: String,
        payload_hex: String,
        want_hex: String,
    }
    #[derive(Deserialize)]
    struct FrameOuterParseCase {
        name: String,
        raw_hex: String,
        #[serde(default)]
        want_channel_hex: String,
        #[serde(default)]
        want_payload_hex: String,
        #[serde(default)]
        expect_error: String,
    }

    #[test]
    fn vectors_frame_outer() {
        let v: FrameOuterVectors = load_vectors("frame_outer.json");

        for c in &v.encode {
            let channel = Channel(hex_decode(&c.channel_hex)[0]);
            let payload = hex_decode(&c.payload_hex);
            let got = encode_outer(channel, &payload);
            assert_eq!(hex_encode(&got), c.want_hex, "case {}", c.name);
        }

        for c in &v.parse {
            let raw = hex_decode(&c.raw_hex);
            let result = parse_outer(&raw);
            if !c.expect_error.is_empty() {
                let err = result.expect_err(&format!("case {}: expected an error", c.name));
                assert_eq!(error_code(err), c.expect_error, "case {}", c.name);
                continue;
            }
            let (hdr, payload) =
                result.unwrap_or_else(|e| panic!("case {}: unexpected error: {e}", c.name));
            assert_eq!(
                hex_encode(&[hdr.channel.0]),
                c.want_channel_hex,
                "case {} channel",
                c.name
            );
            assert_eq!(
                hex_encode(payload),
                c.want_payload_hex,
                "case {} payload",
                c.name
            );
        }
    }

    #[derive(Deserialize)]
    struct FrameInnerVectors {
        encode: Vec<FrameInnerEncodeCase>,
        decode: Vec<FrameInnerDecodeCase>,
    }
    #[derive(Deserialize)]
    struct FrameInnerEncodeCase {
        name: String,
        type_hex: String,
        stream_id: u32,
        #[serde(default)]
        payload_hex: String,
        #[serde(default)]
        want_hex: String,
        #[serde(default)]
        expect_error: String,
    }
    #[derive(Deserialize)]
    struct FrameInnerDecodeCase {
        name: String,
        buf_hex: String,
        #[serde(default)]
        want_frames: Vec<InnerFrameOut>,
        #[serde(default)]
        expect_error: String,
    }
    #[derive(Deserialize)]
    struct InnerFrameOut {
        type_hex: String,
        stream_id: u32,
        #[serde(default)]
        payload_hex: String,
    }

    #[test]
    fn vectors_frame_inner() {
        let v: FrameInnerVectors = load_vectors("frame_inner.json");

        for c in &v.encode {
            let frame = InnerFrame {
                typ: InnerType(hex_decode(&c.type_hex)[0]),
                stream_id: c.stream_id,
                payload: hex_decode(&c.payload_hex),
            };
            let mut buf = Vec::new();
            let result = encode_inner(&mut buf, &frame);
            if !c.expect_error.is_empty() {
                let err = result.expect_err(&format!("case {}: expected an error", c.name));
                assert_eq!(error_code(err), c.expect_error, "case {}", c.name);
                continue;
            }
            result.unwrap_or_else(|e| panic!("case {}: unexpected error: {e}", c.name));
            assert_eq!(hex_encode(&buf), c.want_hex, "case {}", c.name);
        }

        for c in &v.decode {
            let buf = hex_decode(&c.buf_hex);
            let result = decode_inner_all(&buf);
            if !c.expect_error.is_empty() {
                let err = result.expect_err(&format!("case {}: expected an error", c.name));
                assert_eq!(error_code(err), c.expect_error, "case {}", c.name);
                continue;
            }
            let frames = result.unwrap_or_else(|e| panic!("case {}: unexpected error: {e}", c.name));
            assert_eq!(
                frames.len(),
                c.want_frames.len(),
                "case {} frame count",
                c.name
            );
            for (got, want) in frames.iter().zip(c.want_frames.iter()) {
                assert_eq!(
                    hex_encode(&[got.typ.0]),
                    want.type_hex,
                    "case {} type",
                    c.name
                );
                assert_eq!(got.stream_id, want.stream_id, "case {} stream_id", c.name);
                assert_eq!(
                    hex_encode(&got.payload),
                    want.payload_hex,
                    "case {} payload",
                    c.name
                );
            }
        }
    }

    // Hand-written round-trip/negative tests independent of the vendored
    // vectors, so this file is still self-checking if they're ever stale
    // or missing.

    #[test]
    fn encode_decode_inner_round_trip() {
        let frame = InnerFrame {
            typ: INNER_REQ,
            stream_id: 1,
            payload: b"hello".to_vec(),
        };
        let mut buf = Vec::new();
        encode_inner(&mut buf, &frame).unwrap();
        let frames = decode_inner_all(&buf).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].typ, INNER_REQ);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].payload, b"hello");
    }

    #[test]
    fn encode_decode_inner_concatenated() {
        let frames_in = [
            InnerFrame {
                typ: INNER_REQ,
                stream_id: 3,
                payload: b"req-head".to_vec(),
            },
            InnerFrame {
                typ: INNER_REQ_BODY,
                stream_id: 3,
                payload: b"chunk-1".to_vec(),
            },
            InnerFrame {
                typ: INNER_REQ_END,
                stream_id: 3,
                payload: vec![],
            },
        ];
        let mut buf = Vec::new();
        for f in &frames_in {
            encode_inner(&mut buf, f).unwrap();
        }
        let frames_out = decode_inner_all(&buf).unwrap();
        assert_eq!(frames_out.len(), frames_in.len());
        for (got, want) in frames_out.iter().zip(frames_in.iter()) {
            assert_eq!(got.typ, want.typ);
            assert_eq!(got.stream_id, want.stream_id);
            assert_eq!(got.payload, want.payload);
        }
    }

    #[test]
    fn reserved_inner_types_rejected_on_encode_and_decode() {
        for typ in [INNER_WINDOW_UPDATE, INNER_PING, INNER_PONG] {
            let frame = InnerFrame {
                typ,
                stream_id: 1,
                payload: vec![],
            };
            let mut buf = Vec::new();
            assert_eq!(
                encode_inner(&mut buf, &frame),
                Err(WireError::InnerReservedType)
            );

            let mut raw = vec![0u8; INNER_HEADER_LEN];
            raw[0] = typ.0;
            assert_eq!(
                decode_inner_all(&raw),
                Err(WireError::InnerReservedType)
            );
        }
    }

    #[test]
    fn parse_outer_rejects_reserved_flags() {
        for bit in 1..8 {
            let msg = [0x00u8, 1 << bit, 0xAA];
            assert_eq!(parse_outer(&msg), Err(WireError::ReservedFlagsSet));
        }
    }

    #[test]
    fn parse_outer_rejects_conn_id_in_v1() {
        let msg = [0x01u8, FLAG_CONN_ID, 1, 2, 3, 4, 5, 6, 7, 8, 0xAA];
        assert_eq!(parse_outer(&msg), Err(WireError::ConnIdNotV1));
    }

    #[test]
    fn is_client_initiated_matches_odd_even() {
        assert!(is_client_initiated(1));
        assert!(is_client_initiated(3));
        assert!(!is_client_initiated(0));
        assert!(!is_client_initiated(2));
    }
}
