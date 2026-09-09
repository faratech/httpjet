use bytes::{BufMut, Bytes, BytesMut};

pub const FCGI_VERSION_1: u8 = 1;
pub const FCGI_RESPONDER: u16 = 1;
pub const FCGI_KEEP_CONN: u8 = 1;
const HEADER_LEN: usize = 8;
const MAX_CONTENT_LEN: usize = u16::MAX as usize;
const MAX_PAIR_FIELD_LEN: usize = 0x7fff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
}

impl TryFrom<u8> for RecordType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::BeginRequest,
            2 => Self::AbortRequest,
            3 => Self::EndRequest,
            4 => Self::Params,
            5 => Self::Stdin,
            6 => Self::Stdout,
            7 => Self::Stderr,
            8 => Self::Data,
            _ => return Err(WireError::RecordType),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: RecordType,
    pub request_id: u16,
    pub content: Bytes,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("FastCGI request id must be nonzero")]
    RequestId,
    #[error("unsupported FastCGI version")]
    Version,
    #[error("unsupported FastCGI record type")]
    RecordType,
    #[error("invalid FastCGI reserved byte")]
    Reserved,
    #[error("FastCGI field exceeds protocol bounds")]
    FieldTooLarge,
    #[error("FastCGI parameter block exceeds configured bound")]
    ParamsTooLarge,
}

fn record(kind: RecordType, request_id: u16, content: &[u8]) -> Result<Bytes, WireError> {
    if request_id == 0 {
        return Err(WireError::RequestId);
    }
    if content.len() > MAX_CONTENT_LEN {
        return Err(WireError::FieldTooLarge);
    }
    let padding = (8 - content.len() % 8) % 8;
    let mut out = BytesMut::with_capacity(HEADER_LEN + content.len() + padding);
    out.put_u8(FCGI_VERSION_1);
    out.put_u8(kind as u8);
    out.put_u16(request_id);
    out.put_u16(content.len() as u16);
    out.put_u8(padding as u8);
    out.put_u8(0);
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
    Ok(out.freeze())
}

pub fn begin_request(request_id: u16, keep_connection: bool) -> Result<Bytes, WireError> {
    let mut body = [0_u8; 8];
    body[..2].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
    body[2] = if keep_connection { FCGI_KEEP_CONN } else { 0 };
    record(RecordType::BeginRequest, request_id, &body)
}

fn put_len(out: &mut BytesMut, len: usize) -> Result<(), WireError> {
    if len < 128 {
        out.put_u8(len as u8);
    } else if len <= MAX_PAIR_FIELD_LEN {
        out.put_u32((len as u32) | 0x8000_0000);
    } else {
        return Err(WireError::FieldTooLarge);
    }
    Ok(())
}

/// Encode one bounded PARAMS stream, including its required empty terminator.
pub fn encode_name_value_pairs<N, V, I>(
    request_id: u16,
    pairs: I,
    max_encoded_bytes: usize,
) -> Result<Vec<Bytes>, WireError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    I: IntoIterator<Item = (N, V)>,
{
    if request_id == 0 {
        return Err(WireError::RequestId);
    }
    let mut encoded = BytesMut::new();
    for (name, value) in pairs {
        let name = name.as_ref();
        let value = value.as_ref();
        let prefix = usize::from(name.len() >= 128) * 3 + usize::from(value.len() >= 128) * 3 + 2;
        let added = prefix
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(WireError::ParamsTooLarge)?;
        if added > max_encoded_bytes.saturating_sub(encoded.len()) {
            return Err(WireError::ParamsTooLarge);
        }
        put_len(&mut encoded, name.len())?;
        put_len(&mut encoded, value.len())?;
        encoded.extend_from_slice(name);
        encoded.extend_from_slice(value);
    }
    let mut records = encode_stream(RecordType::Params, request_id, &encoded)?;
    records.push(record(RecordType::Params, request_id, &[])?);
    Ok(records)
}

/// Split a byte stream into protocol-sized records. The caller emits the empty
/// terminator explicitly where the FastCGI stream contract requires one.
pub fn encode_stream(
    kind: RecordType,
    request_id: u16,
    bytes: &[u8],
) -> Result<Vec<Bytes>, WireError> {
    if request_id == 0 {
        return Err(WireError::RequestId);
    }
    bytes
        .chunks(MAX_CONTENT_LEN)
        .map(|chunk| record(kind, request_id, chunk))
        .collect()
}

/// Encode the required empty terminator for PARAMS, STDIN, or STDOUT.
pub fn end_stream(kind: RecordType, request_id: u16) -> Result<Bytes, WireError> {
    record(kind, request_id, &[])
}

/// Encode a responder END_REQUEST record.
pub fn end_request(request_id: u16, app_status: u32) -> Result<Bytes, WireError> {
    let mut content = [0_u8; 8];
    content[..4].copy_from_slice(&app_status.to_be_bytes());
    record(RecordType::EndRequest, request_id, &content)
}

/// Parse exactly one record from the front of `input`; incomplete input is left
/// untouched. The reserved byte is required to be zero; padding contents are
/// opaque per the protocol and are skipped.
pub fn parse_record(input: &mut BytesMut) -> Result<Option<Record>, WireError> {
    if input.len() < HEADER_LEN {
        return Ok(None);
    }
    if input[0] != FCGI_VERSION_1 {
        return Err(WireError::Version);
    }
    let kind = RecordType::try_from(input[1])?;
    let request_id = u16::from_be_bytes([input[2], input[3]]);
    if request_id == 0 {
        return Err(WireError::RequestId);
    }
    let content_len = u16::from_be_bytes([input[4], input[5]]) as usize;
    let padding_len = input[6] as usize;
    if input[7] != 0 {
        return Err(WireError::Reserved);
    }
    let total = HEADER_LEN + content_len + padding_len;
    if input.len() < total {
        return Ok(None);
    }
    let mut frame = input.split_to(total);
    let content = frame.split_off(HEADER_LEN).split_to(content_len).freeze();
    Ok(Some(Record {
        kind,
        request_id,
        content,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_request_round_trips_with_responder_role() {
        let bytes = begin_request(7, true).unwrap();
        let mut input = BytesMut::from(bytes.as_ref());
        let parsed = parse_record(&mut input).unwrap().unwrap();
        assert_eq!(parsed.kind, RecordType::BeginRequest);
        assert_eq!(parsed.request_id, 7);
        assert_eq!(&parsed.content[..3], &[0, 1, FCGI_KEEP_CONN]);
        assert!(parsed.content[3..].iter().all(|byte| *byte == 0));
        assert!(input.is_empty());
    }

    #[test]
    fn params_use_one_and_four_byte_lengths_and_terminate() {
        let long = vec![b'x'; 128];
        let records = encode_name_value_pairs(
            1,
            [(b"A".as_slice(), b"B".as_slice()), (long.as_slice(), b"v")],
            1024,
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        let mut first = BytesMut::from(records[0].as_ref());
        let content = parse_record(&mut first).unwrap().unwrap().content;
        assert_eq!(&content[..4], &[1, 1, b'A', b'B']);
        assert_eq!(&content[4..8], &[0x80, 0, 0, 128]);
        let mut end = BytesMut::from(records[1].as_ref());
        assert!(parse_record(&mut end).unwrap().unwrap().content.is_empty());
    }

    #[test]
    fn stream_splits_at_wire_limit_without_truncation() {
        let body = vec![0x5a; MAX_CONTENT_LEN + 9];
        let records = encode_stream(RecordType::Stdin, 3, &body).unwrap();
        assert_eq!(records.len(), 2);
        let mut recovered = Vec::new();
        for bytes in records {
            let mut input = BytesMut::from(bytes.as_ref());
            recovered.extend_from_slice(&parse_record(&mut input).unwrap().unwrap().content);
        }
        assert_eq!(recovered, body);
    }

    #[test]
    fn bounds_and_malformed_frames_fail_closed() {
        assert_eq!(begin_request(0, false), Err(WireError::RequestId));
        assert_eq!(
            encode_name_value_pairs(1, [("name", "value")], 3),
            Err(WireError::ParamsTooLarge)
        );
        let mut bad = BytesMut::from(&b"\x02\x06\x00\x01\x00\x00\x00\x00"[..]);
        assert_eq!(parse_record(&mut bad), Err(WireError::Version));
        let mut bad = BytesMut::from(&b"\x01\x06\x00\x01\x00\x00\x00\x01"[..]);
        assert_eq!(parse_record(&mut bad), Err(WireError::Reserved));

        let mut padded = record(RecordType::Stdout, 1, b"x").unwrap().to_vec();
        *padded.last_mut().unwrap() = 0xa5;
        assert_eq!(
            parse_record(&mut BytesMut::from(padded.as_slice()))
                .unwrap()
                .unwrap()
                .content,
            Bytes::from_static(b"x")
        );
    }

    #[test]
    fn incomplete_record_consumes_nothing() {
        let encoded = begin_request(1, false).unwrap();
        for end in 0..encoded.len() {
            let mut input = BytesMut::from(&encoded[..end]);
            let before = input.clone();
            assert_eq!(parse_record(&mut input).unwrap(), None);
            assert_eq!(input, before);
        }
    }
}
