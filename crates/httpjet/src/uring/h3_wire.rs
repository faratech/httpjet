//! HTTP/3 wire parsing (RFC 9114): the request-stream frame parser, the control-stream
//! and SETTINGS parsers, and the error codes they report. No QUIC or runtime types: std,
//! bytes, hj-core and the sibling `qpack`/`codec` modules only, so the fuzz workspace can
//! include this file directly.

use bytes::Bytes;

use super::qpack::qpack_decode_limited;

pub(super) const H3_NO_ERROR: u32 = 0x0100;
pub(super) const H3_INTERNAL_ERROR: u32 = 0x0102;
pub(super) const H3_STREAM_CREATION_ERROR: u32 = 0x0103;
pub(super) const H3_CLOSED_CRITICAL_STREAM: u32 = 0x0104;
pub(super) const H3_FRAME_UNEXPECTED: u32 = 0x0105;
pub(super) const H3_EXCESSIVE_LOAD: u32 = 0x0107;
pub(super) const H3_SETTINGS_ERROR: u32 = 0x0109;
pub(super) const H3_MISSING_SETTINGS: u32 = 0x010a;
pub(super) const H3_REQUEST_CANCELLED: u32 = 0x010c;
pub(super) const H3_MESSAGE_ERROR: u32 = 0x010e;
pub(super) const MAX_SETTINGS_PAYLOAD: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct H3RequestLimits {
    pub(super) max_header_bytes: usize,
    pub(super) max_body_bytes: usize,
    pub(super) max_request_wire_bytes: usize,
    pub(super) max_connection_bytes: usize,
}

impl H3RequestLimits {
    pub(crate) fn new(max_header_bytes: usize, max_body_bytes: usize) -> Self {
        let framing_allowance = 64 * 1024;
        let max_request_wire_bytes = max_header_bytes
            .saturating_add(max_body_bytes)
            .saturating_add(framing_allowance);
        let max_connection_bytes = max_body_bytes.saturating_mul(4).max(max_request_wire_bytes);
        Self {
            max_header_bytes,
            max_body_bytes,
            max_request_wire_bytes,
            max_connection_bytes,
        }
    }
}

pub(super) struct ParsedH3Request {
    pub(super) field: Vec<u8>,
    pub(super) body: Bytes,
    pub(super) trailers: Option<Vec<u8>>,
}

/// A decoded request field section and its RFC 9114 §4.2.2 size.
pub(super) type DecodedFieldSection = (Vec<(Vec<u8>, Vec<u8>)>, usize);

/// The request head as the frame counter sees it. It is decoded when the first DATA
/// frame header arrives (a body-less request is never decoded here), so a declared
/// content-length bounds the body while it is received (#1049). Dispatch reuses it.
#[derive(Default)]
pub(super) enum H3RequestHead {
    #[default]
    Pending,
    /// QPACK rejected the field section; dispatch answers 400.
    Undecodable,
    Decoded {
        fields: DecodedFieldSection,
        content_length: Option<usize>,
    },
}

fn decode_request_head(field: &[u8], max_header_bytes: usize) -> H3RequestHead {
    let Some(fields) = qpack_decode_limited(field, max_header_bytes) else {
        return H3RequestHead::Undecodable;
    };
    // An unresolvable length is left to dispatch, which answers 400 for it.
    let content_length = super::codec::resolve_content_length(
        fields
            .0
            .iter()
            .filter(|(name, _)| name.as_slice() == b"content-length")
            .map(|(_, value)| value.as_slice()),
    )
    .ok()
    .flatten();
    H3RequestHead::Decoded {
        fields,
        content_length,
    }
}

/// Heap a decoded field section retains until dispatch: each field's slot and its
/// owned name and value, plus RFC 9114's 32 bytes per field for allocator rounding.
/// A one-byte static reference decodes to about 80 bytes, so this, not the wire
/// size, is what the request must hold against its budgets.
fn decoded_head_footprint(fields: &[(Vec<u8>, Vec<u8>)], slots: usize) -> usize {
    fields.iter().fold(
        slots.saturating_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>)>()),
        |sum, (name, value)| {
            sum.saturating_add(32)
                .saturating_add(name.capacity())
                .saturating_add(value.capacity())
        },
    )
}

/// Frames one request may carry that advance neither its head nor its body: empty
/// DATA or HEADERS, and extension or reserved (grease) frames. A client sends a
/// handful; each costs a frame parse but no buffered progress, so a flood of them is
/// closed with H3_EXCESSIVE_LOAD (H2 bounds the same class at this count).
pub(super) const H3_NO_PROGRESS_FRAMES: u32 = 10_000;

/// Incremental parser for one request stream. The receive path validates every frame
/// once, as it arrives, and keeps only what dispatch needs: the field sections and the
/// DATA payloads, compacted into the stream's body buffer. Dispatch never reparses.
#[derive(Default)]
pub(super) struct H3FrameCounter {
    pub(super) phase: H3FramePhase,
    pub(super) varint: [u8; 8],
    pub(super) varint_len: usize,
    pub(super) varint_need: usize,
    pub(super) frame_type: u64,
    pub(super) header_bytes: usize,
    pub(super) body_bytes: usize,
    /// Request-stream bytes received, framing included.
    pub(super) wire_bytes: usize,
    /// Bytes this stream holds against the connection's `total_req_bytes`: its wire
    /// bytes and its decoded head.
    pub(super) charged: usize,
    /// [`decoded_head_footprint`] of `head` once decoded.
    pub(super) head_footprint: usize,
    pub(super) no_progress_frames: u32,
    /// The first HEADERS frame's payload (the request field section).
    pub(super) field: Option<Vec<u8>>,
    pub(super) trailers: Option<Vec<u8>>,
    /// The frame sequence is not a request (dispatch answers 400): DATA before the
    /// head or after trailers, or a third HEADERS frame.
    pub(super) malformed: bool,
    pub(super) head: H3RequestHead,
}

#[derive(Clone, Copy, Default)]
pub(super) enum H3FramePhase {
    #[default]
    Type,
    Length,
    Payload(usize, PayloadSink),
}

/// Where a frame payload's bytes are kept.
#[derive(Clone, Copy)]
pub(super) enum PayloadSink {
    Field,
    Trailers,
    Body,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestFrameError {
    Limit,
    Unexpected,
    /// The request's header section is over `maxReqHeaderSize`: answered 431, as H1/H2.
    HeadersTooLarge,
    /// The body is over the configured maximum and its head decoded: answered 413.
    TooLarge,
    /// DATA past the declared content-length (RFC 9114 §4.1.2): H3_MESSAGE_ERROR.
    Malformed,
    /// Over [`H3_NO_PROGRESS_FRAMES`]: the connection is closed with H3_EXCESSIVE_LOAD.
    ExcessiveLoad,
}

fn request_frame_forbidden(frame_type: u64) -> bool {
    matches!(
        frame_type,
        0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0d
    )
}

impl H3FrameCounter {
    fn reset_varint(&mut self) {
        self.varint_len = 0;
        self.varint_need = 0;
    }

    fn consume_varint(&mut self, input: &[u8], pos: &mut usize) -> Option<u64> {
        while *pos < input.len() {
            let byte = input[*pos];
            *pos += 1;
            if self.varint_len == 0 {
                self.varint_need = 1usize << (byte >> 6);
            }
            self.varint[self.varint_len] = byte;
            self.varint_len += 1;
            if self.varint_len == self.varint_need {
                let mut value = u64::from(self.varint[0] & 0x3f);
                for byte in &self.varint[1..self.varint_need] {
                    value = (value << 8) | u64::from(*byte);
                }
                self.reset_varint();
                return Some(value);
            }
        }
        None
    }

    /// Validate `input`, the next bytes of the request stream, appending its DATA
    /// payloads to `body`.
    pub(super) fn consume(
        &mut self,
        input: &[u8],
        body: &mut Vec<u8>,
        limits: H3RequestLimits,
    ) -> Result<(), RequestFrameError> {
        let mut pos = 0usize;
        while pos < input.len() {
            match self.phase {
                H3FramePhase::Type => {
                    let Some(frame_type) = self.consume_varint(input, &mut pos) else {
                        break;
                    };
                    self.frame_type = frame_type;
                    self.phase = H3FramePhase::Length;
                }
                H3FramePhase::Length => {
                    let Some(length) = self.consume_varint(input, &mut pos) else {
                        break;
                    };
                    if request_frame_forbidden(self.frame_type) {
                        return Err(RequestFrameError::Unexpected);
                    }
                    let Ok(length) = usize::try_from(length) else {
                        return Err(RequestFrameError::Limit);
                    };
                    if length == 0 || !matches!(self.frame_type, 0x00 | 0x01) {
                        self.no_progress_frames += 1;
                        if self.no_progress_frames > H3_NO_PROGRESS_FRAMES {
                            return Err(RequestFrameError::ExcessiveLoad);
                        }
                    }
                    let sink = match self.frame_type {
                        0x01 => {
                            let Some(total) = self.header_bytes.checked_add(length) else {
                                return Err(RequestFrameError::HeadersTooLarge);
                            };
                            if total > limits.max_header_bytes {
                                return Err(RequestFrameError::HeadersTooLarge);
                            }
                            self.header_bytes = total;
                            if self.field.is_none() {
                                self.field = Some(Vec::new());
                                PayloadSink::Field
                            } else if self.trailers.is_none() {
                                self.trailers = Some(Vec::new());
                                PayloadSink::Trailers
                            } else {
                                self.malformed = true;
                                PayloadSink::Discard
                            }
                        }
                        0x00 => {
                            self.data_frame(length, limits)?;
                            if self.field.is_none() || self.trailers.is_some() {
                                self.malformed = true;
                            }
                            if self.malformed {
                                PayloadSink::Discard
                            } else {
                                PayloadSink::Body
                            }
                        }
                        _ => PayloadSink::Discard,
                    };
                    self.phase = if length == 0 {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(length, sink)
                    };
                }
                H3FramePhase::Payload(remaining, sink) => {
                    let consumed = remaining.min(input.len() - pos);
                    let payload = &input[pos..pos + consumed];
                    match sink {
                        PayloadSink::Field => self
                            .field
                            .get_or_insert_default()
                            .extend_from_slice(payload),
                        PayloadSink::Trailers => self
                            .trailers
                            .get_or_insert_default()
                            .extend_from_slice(payload),
                        PayloadSink::Body => body.extend_from_slice(payload),
                        PayloadSink::Discard => {}
                    }
                    pos += consumed;
                    self.phase = if consumed == remaining {
                        H3FramePhase::Type
                    } else {
                        H3FramePhase::Payload(remaining - consumed, sink)
                    };
                }
            }
        }
        Ok(())
    }

    /// Admit the next DATA frame's declared `length`. The frame header is checked
    /// before any of its payload is buffered, as H2 checks each DATA frame (#1014).
    fn data_frame(
        &mut self,
        length: usize,
        limits: H3RequestLimits,
    ) -> Result<(), RequestFrameError> {
        if matches!(self.head, H3RequestHead::Pending)
            && let Some(field) = self.field.as_deref()
        {
            self.head = decode_request_head(field, limits.max_header_bytes);
            if let H3RequestHead::Decoded {
                fields: (fields, _),
                ..
            } = &self.head
            {
                self.head_footprint = decoded_head_footprint(fields, fields.capacity());
            }
        }
        let Some(total) = self.body_bytes.checked_add(length) else {
            return Err(RequestFrameError::Limit);
        };
        let declared = match &self.head {
            H3RequestHead::Decoded { content_length, .. } => Some(*content_length),
            _ => None,
        };
        if let Some(Some(content_length)) = declared {
            if content_length > limits.max_body_bytes {
                return Err(RequestFrameError::TooLarge);
            }
            if total > content_length {
                return Err(RequestFrameError::Malformed);
            }
        }
        if total > limits.max_body_bytes {
            // Without a decoded head there is no request to answer.
            return Err(if declared.is_some() {
                RequestFrameError::TooLarge
            } else {
                RequestFrameError::Limit
            });
        }
        self.body_bytes = total;
        Ok(())
    }

    /// The request received through FIN: its field sections, `body` (carrying `lease`)
    /// and the head decoded on the receive path, if any. `None` when the stream does not
    /// hold exactly one request (dispatch answers 400).
    pub(super) fn finish(
        self,
        body: Vec<u8>,
        lease: Option<hj_core::budget::BodyBufferLease>,
    ) -> Option<(ParsedH3Request, Option<DecodedFieldSection>)> {
        let at_frame_boundary = matches!(self.phase, H3FramePhase::Type) && self.varint_len == 0;
        if self.malformed || !at_frame_boundary {
            return None;
        }
        let field = self.field?;
        let body = if body.is_empty() {
            Bytes::new()
        } else {
            match lease {
                // Dispatch consumes the decoded head before its first await; only the
                // wire bytes stay reserved for the body's lifetime.
                Some(mut lease) => {
                    lease.release(self.head_footprint as u64);
                    lease.into_bytes(body)
                }
                None => Bytes::from(body),
            }
        };
        let head = match self.head {
            H3RequestHead::Decoded { fields, .. } => Some(fields),
            _ => None,
        };
        Some((
            ParsedH3Request {
                field,
                body,
                trailers: self.trailers,
            },
            head,
        ))
    }

    #[cfg(test)]
    pub(super) fn decoded_head(&self) -> Option<&DecodedFieldSection> {
        match &self.head {
            H3RequestHead::Decoded { fields, .. } => Some(fields),
            _ => None,
        }
    }
}

#[derive(Default)]
pub(super) struct IncrementalVarInt {
    pub(super) bytes: [u8; 8],
    pub(super) len: usize,
    pub(super) need: usize,
}

impl IncrementalVarInt {
    pub(super) fn consume(&mut self, input: &[u8], pos: &mut usize) -> Option<u64> {
        while *pos < input.len() {
            let byte = input[*pos];
            *pos += 1;
            if self.len == 0 {
                self.need = 1usize << (byte >> 6);
            }
            self.bytes[self.len] = byte;
            self.len += 1;
            if self.len == self.need {
                let mut value = u64::from(self.bytes[0] & 0x3f);
                for byte in &self.bytes[1..self.need] {
                    value = (value << 8) | u64::from(*byte);
                }
                self.len = 0;
                self.need = 0;
                return Some(value);
            }
        }
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PeerSettings {
    pub(super) qpack_max_table_capacity: Option<u64>,
    pub(super) max_field_section_size: Option<u64>,
    pub(super) qpack_blocked_streams: Option<u64>,
    pub(super) enable_connect_protocol: Option<u64>,
    pub(super) h3_datagram: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct H3ConnectionError {
    pub(super) code: u32,
    pub(super) reason: &'static [u8],
}

impl H3ConnectionError {
    pub(super) const fn new(code: u32, reason: &'static [u8]) -> Self {
        Self { code, reason }
    }
}

#[derive(Default)]
pub(super) struct SettingsParser {
    pub(super) varint: IncrementalVarInt,
    pub(super) pending_id: Option<u64>,
    pub(super) seen: std::collections::HashSet<u64>,
    pub(super) parsed: PeerSettings,
}

impl SettingsParser {
    pub(super) fn consume(&mut self, input: &[u8]) -> Result<(), H3ConnectionError> {
        let mut pos = 0;
        while pos < input.len() {
            let Some(value) = self.varint.consume(input, &mut pos) else {
                break;
            };
            if let Some(id) = self.pending_id.take() {
                if !self.seen.insert(id) {
                    return Err(H3ConnectionError::new(
                        H3_SETTINGS_ERROR,
                        b"duplicate HTTP/3 setting",
                    ));
                }
                match id {
                    0x01 => self.parsed.qpack_max_table_capacity = Some(value),
                    0x02..=0x05 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"reserved HTTP/2 setting identifier",
                        ));
                    }
                    0x06 => self.parsed.max_field_section_size = Some(value),
                    0x07 => self.parsed.qpack_blocked_streams = Some(value),
                    0x08 if value <= 1 => self.parsed.enable_connect_protocol = Some(value),
                    0x08 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"invalid enable-connect setting",
                        ));
                    }
                    0x33 if value <= 1 => self.parsed.h3_datagram = Some(value),
                    0x33 => {
                        return Err(H3ConnectionError::new(
                            H3_SETTINGS_ERROR,
                            b"invalid H3 datagram setting",
                        ));
                    }
                    _ => {}
                }
            } else {
                self.pending_id = Some(value);
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<PeerSettings, H3ConnectionError> {
        if self.varint.len != 0 || self.pending_id.is_some() {
            Err(H3ConnectionError::new(
                H3_SETTINGS_ERROR,
                b"truncated HTTP/3 setting",
            ))
        } else {
            Ok(self.parsed)
        }
    }
}

#[derive(Default)]
pub(super) struct ControlStreamParser {
    pub(super) phase: ControlFramePhase,
    pub(super) varint: IncrementalVarInt,
    pub(super) frame_type: u64,
    pub(super) settings_received: bool,
    pub(super) settings: Option<SettingsParser>,
    pub(super) completed_settings: Option<PeerSettings>,
}

#[derive(Clone, Copy, Default)]
pub(super) enum ControlFramePhase {
    #[default]
    Type,
    Length,
    Payload(usize),
}

impl ControlStreamParser {
    fn finish_payload(&mut self) -> Result<(), H3ConnectionError> {
        if self.frame_type == 0x04 {
            let settings = self.settings.take().unwrap_or_default().finish()?;
            self.completed_settings = Some(settings);
        }
        self.phase = ControlFramePhase::Type;
        Ok(())
    }

    pub(super) fn consume(&mut self, input: &[u8]) -> Result<(), H3ConnectionError> {
        let mut pos = 0;
        while pos < input.len() {
            match self.phase {
                ControlFramePhase::Type => {
                    let Some(frame_type) = self.varint.consume(input, &mut pos) else {
                        break;
                    };
                    if !self.settings_received && frame_type != 0x04 {
                        return Err(H3ConnectionError::new(
                            H3_MISSING_SETTINGS,
                            b"SETTINGS is not the first control frame",
                        ));
                    }
                    if frame_type == 0x04 && self.settings_received {
                        return Err(H3ConnectionError::new(
                            H3_FRAME_UNEXPECTED,
                            b"duplicate SETTINGS frame",
                        ));
                    }
                    if matches!(frame_type, 0x00 | 0x01 | 0x02 | 0x05 | 0x06 | 0x08 | 0x09) {
                        return Err(H3ConnectionError::new(
                            H3_FRAME_UNEXPECTED,
                            b"frame is forbidden on the control stream",
                        ));
                    }
                    self.frame_type = frame_type;
                    self.phase = ControlFramePhase::Length;
                }
                ControlFramePhase::Length => {
                    let Some(length) = self.varint.consume(input, &mut pos) else {
                        break;
                    };
                    let length = usize::try_from(length).map_err(|_| {
                        H3ConnectionError::new(H3_SETTINGS_ERROR, b"control frame too large")
                    })?;
                    if self.frame_type == 0x04 {
                        if length > MAX_SETTINGS_PAYLOAD {
                            return Err(H3ConnectionError::new(
                                H3_EXCESSIVE_LOAD,
                                b"HTTP/3 SETTINGS payload is excessive",
                            ));
                        }
                        self.settings_received = true;
                        self.settings = Some(SettingsParser::default());
                    }
                    if length == 0 {
                        self.finish_payload()?;
                    } else {
                        self.phase = ControlFramePhase::Payload(length);
                    }
                }
                ControlFramePhase::Payload(remaining) => {
                    let consumed = remaining.min(input.len() - pos);
                    if self.frame_type == 0x04 {
                        self.settings
                            .as_mut()
                            .expect("SETTINGS parser exists while its payload is active")
                            .consume(&input[pos..pos + consumed])?;
                    }
                    pos += consumed;
                    if consumed == remaining {
                        self.finish_payload()?;
                    } else {
                        self.phase = ControlFramePhase::Payload(remaining - consumed);
                    }
                }
            }
        }
        Ok(())
    }
}
