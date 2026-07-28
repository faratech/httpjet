//! HTTP/2 frame codec (RFC 7540 §4.1 + §6).
//!
//! Every frame begins with a fixed 9-octet header: a 24-bit length, an 8-bit type,
//! 8-bit flags, a reserved bit, and a 31-bit stream identifier. This module parses
//! and serializes that header plus the small fixed-shape frames the server both
//! receives and emits (SETTINGS, WINDOW_UPDATE, RST_STREAM, GOAWAY, PING). DATA and
//! HEADERS payloads are opaque byte runs handled by the connection layer (the latter
//! via [`crate`]'s HPACK), so only their headers live here.

/// Frame type codes (RFC 7540 §6).
pub mod kind {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// Frame flags (RFC 7540 §6). Note `ACK` (SETTINGS/PING) and `END_STREAM` (DATA/
/// HEADERS) share bit 0x1 but never apply to the same frame type.
pub mod flags {
    pub const ACK: u8 = 0x1;
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// SETTINGS parameter identifiers (RFC 7540 §6.5.2).
pub mod settings {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// Error codes (RFC 7540 §7).
pub mod error_code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const CONNECT_ERROR: u32 = 0xa;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;
}

/// The fixed 9-octet frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Length of the frame payload (24-bit; does not include this 9-byte header).
    pub length: u32,
    pub kind: u8,
    pub flags: u8,
    /// 31-bit stream identifier (0 = connection control).
    pub stream_id: u32,
}

impl FrameHeader {
    /// Serialized size of the header itself.
    pub const LEN: usize = 9;

    /// Parse a frame header from the first 9 bytes of `buf`. Returns `None` if `buf`
    /// is shorter than 9 bytes. The reserved high bit of the stream id is masked off.
    pub fn parse(buf: &[u8]) -> Option<FrameHeader> {
        let h = buf.get(..Self::LEN)?;
        let length = u32::from(h[0]) << 16 | u32::from(h[1]) << 8 | u32::from(h[2]);
        let kind = h[3];
        let flags = h[4];
        let stream_id = (u32::from(h[5]) << 24
            | u32::from(h[6]) << 16
            | u32::from(h[7]) << 8
            | u32::from(h[8]))
            & 0x7fff_ffff;
        Some(FrameHeader {
            length,
            kind,
            flags,
            stream_id,
        })
    }

    /// Append the serialized 9-octet header to `out` (reserved bit cleared).
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push((self.length >> 16) as u8);
        out.push((self.length >> 8) as u8);
        out.push(self.length as u8);
        out.push(self.kind);
        out.push(self.flags);
        let sid = self.stream_id & 0x7fff_ffff;
        out.extend_from_slice(&sid.to_be_bytes());
    }
}

/// Append a complete frame (header sized to `payload`) followed by its payload.
pub fn write_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    FrameHeader {
        length: payload.len() as u32,
        kind,
        flags,
        stream_id,
    }
    .write(out);
    out.extend_from_slice(payload);
}

/// Append an empty SETTINGS ACK frame (RFC 7540 §6.5).
pub fn write_settings_ack(out: &mut Vec<u8>) {
    write_frame(out, kind::SETTINGS, flags::ACK, 0, &[]);
}

/// Append a SETTINGS frame carrying the given `(id, value)` parameters.
pub fn write_settings(out: &mut Vec<u8>, params: &[(u16, u32)]) {
    let mut payload = Vec::with_capacity(params.len() * 6);
    for (id, value) in params {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    write_frame(out, kind::SETTINGS, 0, 0, &payload);
}

/// Append a WINDOW_UPDATE frame granting `increment` to `stream_id` (0 = connection).
pub fn write_window_update(out: &mut Vec<u8>, stream_id: u32, increment: u32) {
    write_frame(
        out,
        kind::WINDOW_UPDATE,
        0,
        stream_id,
        &(increment & 0x7fff_ffff).to_be_bytes(),
    );
}

/// Append an RST_STREAM frame closing `stream_id` with `error_code`.
pub fn write_rst_stream(out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    write_frame(
        out,
        kind::RST_STREAM,
        0,
        stream_id,
        &error_code.to_be_bytes(),
    );
}

/// Append a GOAWAY frame (last processed stream id + error code, no debug data).
pub fn write_goaway(out: &mut Vec<u8>, last_stream_id: u32, error_code: u32) {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    write_frame(out, kind::GOAWAY, 0, 0, &payload);
}

/// Append a PING ACK echoing the received 8-byte opaque payload.
pub fn write_ping_ack(out: &mut Vec<u8>, opaque: [u8; 8]) {
    write_frame(out, kind::PING, flags::ACK, 0, &opaque);
}

/// Iterate the `(id, value)` parameters of a SETTINGS payload. Returns `None` if the
/// payload length is not a multiple of 6 (a connection error per §6.5).
pub fn parse_settings(payload: &[u8]) -> Option<impl Iterator<Item = (u16, u32)> + '_> {
    if !payload.len().is_multiple_of(6) {
        return None;
    }
    Some(payload.chunks_exact(6).map(|c| {
        let id = u16::from_be_bytes([c[0], c[1]]);
        let value = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
        (id, value)
    }))
}

/// Parse a WINDOW_UPDATE payload into its 31-bit increment (`None` if not 4 bytes).
pub fn parse_window_update(payload: &[u8]) -> Option<u32> {
    let b: [u8; 4] = payload.try_into().ok()?;
    Some(u32::from_be_bytes(b) & 0x7fff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = FrameHeader {
            length: 0x123456,
            kind: kind::HEADERS,
            flags: flags::END_HEADERS,
            stream_id: 1,
        };
        let mut out = Vec::new();
        h.write(&mut out);
        assert_eq!(out.len(), FrameHeader::LEN);
        assert_eq!(
            out,
            vec![0x12, 0x34, 0x56, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(FrameHeader::parse(&out), Some(h));
    }

    #[test]
    fn reserved_bit_is_masked() {
        // A stream id with the top (reserved) bit set must parse as the low 31 bits.
        let raw = [0, 0, 0, kind::DATA, 0, 0x80, 0x00, 0x00, 0x05];
        assert_eq!(FrameHeader::parse(&raw).unwrap().stream_id, 5);
    }

    #[test]
    fn parse_short_is_none() {
        assert_eq!(FrameHeader::parse(&[0u8; 8]), None);
    }

    #[test]
    fn settings_roundtrip() {
        let mut out = Vec::new();
        write_settings(
            &mut out,
            &[
                (settings::INITIAL_WINDOW_SIZE, 1 << 21),
                (settings::MAX_FRAME_SIZE, 16384),
            ],
        );
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::SETTINGS);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.length, 12);
        let params: Vec<_> = parse_settings(&out[FrameHeader::LEN..]).unwrap().collect();
        assert_eq!(
            params,
            vec![
                (settings::INITIAL_WINDOW_SIZE, 1 << 21),
                (settings::MAX_FRAME_SIZE, 16384)
            ]
        );
    }

    #[test]
    fn settings_ack_is_empty_with_ack_flag() {
        let mut out = Vec::new();
        write_settings_ack(&mut out);
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::SETTINGS);
        assert_eq!(hdr.flags, flags::ACK);
        assert_eq!(hdr.length, 0);
        assert_eq!(out.len(), FrameHeader::LEN);
    }

    #[test]
    fn window_update_roundtrip() {
        let mut out = Vec::new();
        write_window_update(&mut out, 3, 65535);
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::WINDOW_UPDATE);
        assert_eq!(hdr.stream_id, 3);
        assert_eq!(parse_window_update(&out[FrameHeader::LEN..]), Some(65535));
    }

    #[test]
    fn goaway_and_rst_and_ping() {
        let mut out = Vec::new();
        write_goaway(&mut out, 7, error_code::NO_ERROR);
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::GOAWAY);
        assert_eq!(hdr.length, 8);

        out.clear();
        write_rst_stream(&mut out, 5, error_code::CANCEL);
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::RST_STREAM);
        assert_eq!(hdr.stream_id, 5);
        assert_eq!(
            u32::from_be_bytes(out[FrameHeader::LEN..].try_into().unwrap()),
            error_code::CANCEL
        );

        out.clear();
        write_ping_ack(&mut out, [1, 2, 3, 4, 5, 6, 7, 8]);
        let hdr = FrameHeader::parse(&out).unwrap();
        assert_eq!(hdr.kind, kind::PING);
        assert_eq!(hdr.flags, flags::ACK);
        assert_eq!(&out[FrameHeader::LEN..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn settings_bad_length_rejected() {
        assert!(parse_settings(&[0u8; 5]).is_none());
        assert!(parse_settings(&[0u8; 12]).is_some());
    }
}
