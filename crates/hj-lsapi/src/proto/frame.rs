//! LSAPI wire frames: the [`LsapiFrame`] type, the [`LsapiCodec`]
//! ([`Encoder`]/[`Decoder`]) that adds/strips the 8-byte packet header, and the
//! RESP_HEADER parser ([`RespHeader`] / [`parse_resp_header`]).
//!
//! The packet *builders* (BEGIN_REQUEST assembly) live in [`super::builder`];
//! the shared constants + [`PacketType`] come from the parent [`super`] module.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::*;

/// A raw LSAPI frame: a type plus an already-assembled body (the body does NOT
/// include the 8-byte packet header — the codec adds/strips that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsapiFrame {
    pub ptype: PacketType,
    pub body: Bytes,
    /// The sender's `m_flag` (endianness bit) from the packet header, retained so the
    /// body's int32/u16 fields are decoded with the SAME endianness convention the length
    /// was — see [`RespHeader::parse_flagged`]. Outbound/synthetic frames default to this
    /// host's endianness (what the encoder writes), so a round-trip stays consistent.
    pub flag: u8,
}

impl LsapiFrame {
    pub fn new(ptype: PacketType, body: impl Into<Bytes>) -> Self {
        LsapiFrame {
            ptype,
            body: body.into(),
            flag: HOST_LSAPI_ENDIAN,
        }
    }

    /// A header-only control frame (RESP_END, ABORT_REQUEST, CONN_CLOSE, ...).
    pub fn control(ptype: PacketType) -> Self {
        LsapiFrame {
            ptype,
            body: Bytes::new(),
            flag: HOST_LSAPI_ENDIAN,
        }
    }
}

/// `tokio_util` codec for the LSAPI wire format. Encodes [`LsapiFrame`]s (adding
/// the 8-byte header with a little-endian length that includes the header) and
/// decodes inbound packets (honoring the sender's endianness flag for the length).
#[derive(Debug, Default, Clone)]
pub struct LsapiCodec {
    /// `(total_len, m_flag)` of the in-progress packet once the header is parsed, else
    /// `None`. The flag is retained so the emitted frame carries the sender's endianness.
    expected: Option<(usize, u8)>,
}

impl LsapiCodec {
    pub fn new() -> Self {
        LsapiCodec { expected: None }
    }

    /// Write an 8-byte packet header (little-endian length, header-inclusive).
    fn put_header(dst: &mut BytesMut, ptype: PacketType, total_len: usize) {
        dst.put_u8(VERSION_B0);
        dst.put_u8(VERSION_B1);
        dst.put_u8(ptype as u8);
        // m_flag = this host's LSAPI_ENDIAN (BIG on aarch64) so lsphp does not
        // byte-swap our request length; the length bytes stay host-native (LE on
        // every arch httpjet targets).
        dst.put_u8(HOST_LSAPI_ENDIAN);
        dst.put_u32_le(total_len as u32);
    }
}

impl Encoder<LsapiFrame> for LsapiCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: LsapiFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let total = PACKET_HEADER_LEN + item.body.len();
        dst.reserve(total);
        LsapiCodec::put_header(dst, item.ptype, total);
        dst.extend_from_slice(&item.body);
        Ok(())
    }
}

impl Decoder for LsapiCodec {
    type Item = LsapiFrame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (total, flag) = match self.expected {
            Some(t) => t,
            None => {
                if src.len() < PACKET_HEADER_LEN {
                    return Ok(None);
                }
                if src[0] != VERSION_B0 || src[1] != VERSION_B1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "LSAPI: bad packet magic",
                    ));
                }
                let flag = src[3];
                let len_bytes = [src[4], src[5], src[6], src[7]];
                // lsphp writes the length host-native (LE on every arch we run on)
                // and flags it with this host's LSAPI_ENDIAN. Swap ONLY on a true
                // cross-endian mismatch (never for a co-located lsphp).
                let total = if flag & ENDIAN_BIT == HOST_LSAPI_ENDIAN {
                    u32::from_le_bytes(len_bytes)
                } else {
                    u32::from_be_bytes(len_bytes)
                } as usize;
                if !(PACKET_HEADER_LEN..=MAX_PACKET_LEN).contains(&total) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("LSAPI: implausible packet length {total}"),
                    ));
                }
                self.expected = Some((total, flag));
                (total, flag)
            }
        };

        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        // We have a whole packet. Validate type from the header byte we left in place.
        let type_byte = src[2];
        let ptype = PacketType::from_u8(type_byte).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("LSAPI: unknown packet type {type_byte}"),
            )
        })?;

        let mut packet = src.split_to(total);
        packet.advance(PACKET_HEADER_LEN);
        self.expected = None;
        Ok(Some(LsapiFrame {
            ptype,
            body: packet.freeze(),
            flag,
        }))
    }
}

/// A parsed RESP_HEADER: the HTTP status code and the response header lines
/// (`(name, value)` pairs, with surrounding whitespace trimmed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespHeader {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// Parse a RESP_HEADER packet body (everything after the 8-byte packet header).
///
/// `little_endian` selects how the int32/u16 fields are read; callers normally
/// pass `true` because the local server and lsphp run with the same endianness
/// and we always emit little-endian. (Use [`RespHeader::parse_flagged`] when you
/// still have the raw header flag byte.)
pub fn parse_resp_header(mut body: &[u8], little_endian: bool) -> std::io::Result<RespHeader> {
    fn bad(msg: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("LSAPI RESP_HEADER: {msg}"),
        )
    }
    if body.len() < 8 {
        return Err(bad("truncated resp_info"));
    }
    let rd_i32 = |b: &mut &[u8]| -> i32 {
        let v = if little_endian {
            i32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            i32::from_be_bytes([b[0], b[1], b[2], b[3]])
        };
        *b = &b[4..];
        v
    };
    let rd_u16 = |b: &mut &[u8]| -> u16 {
        let v = if little_endian {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        };
        *b = &b[2..];
        v
    };

    let cnt = rd_i32(&mut body);
    let status = rd_i32(&mut body);
    if !(0..=4096).contains(&cnt) {
        return Err(bad("implausible header count"));
    }
    let cnt = cnt as usize;
    if !(0..=599).contains(&status) {
        return Err(bad("implausible status"));
    }

    if body.len() < cnt * 2 {
        return Err(bad("truncated length array"));
    }
    let mut lens = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        lens.push(rd_u16(&mut body) as usize);
    }

    let mut headers = Vec::with_capacity(cnt);
    for len in lens {
        if body.len() < len {
            return Err(bad("truncated header strings"));
        }
        let (line, rest) = body.split_at(len);
        body = rest;
        // strip a single trailing NUL that the length counts.
        let line = match line.last() {
            Some(0) => &line[..line.len() - 1],
            _ => line,
        };
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        } else if !line.trim().is_empty() {
            // tolerate a bare line by treating it as a header with empty value
            headers.push((line.trim().to_string(), String::new()));
        }
    }

    Ok(RespHeader {
        status: status as u16,
        headers,
    })
}

impl RespHeader {
    /// Parse from a frame's body using the original packet flag byte. The endianness
    /// convention MUST match the length decode in the codec: lsphp writes the body's
    /// int32/u16 fields host-native (LE on every arch httpjet runs on) and stamps the
    /// flag with its own `LSAPI_ENDIAN`, so a flag that EQUALS this host's endianness
    /// means "no swap → read LE". (Comparing to `ENDIAN_LITTLE` instead would mis-decode
    /// on aarch64, whose `LSAPI_ENDIAN` is BIG even though the bytes are physically LE.)
    pub fn parse_flagged(body: &[u8], flag: u8) -> std::io::Result<RespHeader> {
        parse_resp_header(body, flag & ENDIAN_BIT == HOST_LSAPI_ENDIAN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrips_a_control_frame() {
        let mut codec = LsapiCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(LsapiFrame::control(PacketType::RespEnd), &mut buf)
            .unwrap();
        // header-only packet: 8 bytes, length field == 8 LE.
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[..2], b"LS");
        assert_eq!(buf[2], PacketType::RespEnd as u8);
        assert_eq!(buf[3], HOST_LSAPI_ENDIAN);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 8);

        let mut dcodec = LsapiCodec::new();
        let frame = dcodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::RespEnd);
        assert!(frame.body.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn codec_roundtrips_a_stream_frame() {
        let payload = b"hello lsapi body".to_vec();
        let mut codec = LsapiCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                LsapiFrame::new(PacketType::RespStream, payload.clone()),
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf.len(), 8 + payload.len());
        let mut dcodec = LsapiCodec::new();
        let frame = dcodec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::RespStream);
        assert_eq!(&frame.body[..], &payload[..]);
    }

    #[test]
    fn codec_handles_partial_then_complete() {
        let payload = b"abcdefghij".to_vec();
        let mut enc = LsapiCodec::new();
        let mut full = BytesMut::new();
        enc.encode(
            LsapiFrame::new(PacketType::StderrStream, payload.clone()),
            &mut full,
        )
        .unwrap();

        let mut dec = LsapiCodec::new();
        // feed header only
        let mut partial = BytesMut::from(&full[..8]);
        assert!(dec.decode(&mut partial).unwrap().is_none());
        // feed a couple body bytes
        partial.extend_from_slice(&full[8..12]);
        assert!(dec.decode(&mut partial).unwrap().is_none());
        // feed the rest
        partial.extend_from_slice(&full[12..]);
        let frame = dec.decode(&mut partial).unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::StderrStream);
        assert_eq!(&frame.body[..], &payload[..]);
    }

    #[test]
    fn codec_decodes_big_endian_length_flag() {
        // Hand-build a RESP_STREAM packet that claims big-endian in the flag.
        let body = b"BE";
        let total: u32 = 8 + body.len() as u32;
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION_B0);
        buf.put_u8(VERSION_B1);
        buf.put_u8(PacketType::RespStream as u8);
        buf.put_u8(ENDIAN_BIG);
        buf.put_u32(total); // BufMut::put_u32 is big-endian
        buf.extend_from_slice(body);

        let mut dec = LsapiCodec::new();
        let frame = dec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::RespStream);
        assert_eq!(&frame.body[..], body);
    }

    #[test]
    fn resp_header_parses() {
        // Build a RESP_HEADER body the way lsphp would (little-endian).
        let lines: [&str; 2] = [
            "Content-Type: text/html; charset=UTF-8",
            "X-Powered-By: PHP/8",
        ];
        let mut body = BytesMut::new();
        body.put_i32_le(lines.len() as i32); // m_cntHeaders
        body.put_i32_le(200); // m_status
        // length array: each line length includes trailing NUL
        for l in &lines {
            body.put_u16_le((l.len() + 1) as u16);
        }
        for l in &lines {
            body.extend_from_slice(l.as_bytes());
            body.put_u8(0);
        }

        let parsed = parse_resp_header(&body, true).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.headers[0].0, "Content-Type");
        assert_eq!(parsed.headers[0].1, "text/html; charset=UTF-8");
        assert_eq!(parsed.headers[1].0, "X-Powered-By");
        assert_eq!(parsed.headers[1].1, "PHP/8");
    }

    #[test]
    fn parse_flagged_honors_host_endianness_not_literal_little() {
        // A RESP_HEADER body as lsphp writes it: host-native (LE on every arch we run on).
        let mut body = BytesMut::new();
        body.put_i32_le(1); // m_cntHeaders
        body.put_i32_le(200); // m_status
        let line = "X-Test: ok";
        body.put_u16_le((line.len() + 1) as u16);
        body.extend_from_slice(line.as_bytes());
        body.put_u8(0);

        // A frame flagged with THIS host's endianness decodes the host-native (LE) body —
        // mirroring the codec's length decode, which also compares to HOST_LSAPI_ENDIAN.
        let h = RespHeader::parse_flagged(&body, HOST_LSAPI_ENDIAN).unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.headers, vec![("X-Test".to_string(), "ok".to_string())]);

        // A genuinely cross-endian peer flag flips the decode to big-endian: the LE body then
        // reads as an implausible count (an error), proving the flag is honored, not ignored.
        // (Before the fix, parse_flagged compared to ENDIAN_LITTLE and would mis-handle aarch64.)
        let cross = HOST_LSAPI_ENDIAN ^ ENDIAN_BIT;
        assert!(RespHeader::parse_flagged(&body, cross).is_err());
    }

    #[test]
    fn full_begin_request_roundtrips_through_codec() {
        let env = vec![
            ("REQUEST_METHOD".to_string(), "POST".to_string()),
            ("SCRIPT_FILENAME".to_string(), "/x/y.php".to_string()),
            ("SCRIPT_NAME".to_string(), "/y.php".to_string()),
            ("QUERY_STRING".to_string(), String::new()),
        ];
        let body = build_begin_request_body(&env, b"payload".len() as i32);
        let mut codec = LsapiCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                LsapiFrame::new(PacketType::BeginRequest, body.clone()),
                &mut buf,
            )
            .unwrap();
        let mut dec = LsapiCodec::new();
        let frame = dec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.ptype, PacketType::BeginRequest);
        assert_eq!(frame.body, body);
    }
}
