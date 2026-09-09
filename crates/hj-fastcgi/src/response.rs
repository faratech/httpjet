use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

#[derive(Debug)]
pub struct CgiHead {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body_prefix: Bytes,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResponseError {
    #[error("FastCGI response headers are incomplete")]
    Incomplete,
    #[error("FastCGI response headers exceed configured bounds")]
    TooLarge,
    #[error("FastCGI response header is malformed")]
    Malformed,
    #[error("FastCGI application did not complete the request")]
    IncompleteRequest,
}

/// Parse a complete CGI header block plus any already-buffered body prefix.
/// Only CRLF framing is accepted; folded and hop-by-hop fields fail closed.
pub fn parse_cgi_head(
    bytes: Bytes,
    max_header_bytes: usize,
    max_headers: usize,
) -> Result<CgiHead, ResponseError> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ResponseError::Incomplete)?;
    let head_len = boundary + 4;
    if head_len > max_header_bytes || max_headers == 0 {
        return Err(ResponseError::TooLarge);
    }
    let mut status = None;
    let mut headers = HeaderMap::new();
    let mut count = 0_usize;
    let mut lines = bytes[..boundary].split(|byte| *byte == b'\n').peekable();
    while let Some(raw) = lines.next() {
        let line = if let Some(line) = raw.strip_suffix(b"\r") {
            line
        } else if lines.peek().is_none() {
            raw
        } else {
            return Err(ResponseError::Malformed);
        };
        if line.is_empty() || matches!(line.first(), Some(b' ' | b'\t')) {
            return Err(ResponseError::Malformed);
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(ResponseError::Malformed)?;
        let name = HeaderName::from_bytes(&line[..colon]).map_err(|_| ResponseError::Malformed)?;
        let value = line[colon + 1..]
            .strip_prefix(b" ")
            .unwrap_or(&line[colon + 1..]);
        if name == "status" {
            if status.is_some() {
                return Err(ResponseError::Malformed);
            }
            let code = value
                .split(|byte| *byte == b' ')
                .next()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse::<u16>().ok())
                .and_then(|value| StatusCode::from_u16(value).ok())
                .ok_or(ResponseError::Malformed)?;
            status = Some(code);
            continue;
        }
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "trailer"
        ) {
            return Err(ResponseError::Malformed);
        }
        count += 1;
        if count > max_headers {
            return Err(ResponseError::TooLarge);
        }
        headers.append(
            name,
            HeaderValue::from_bytes(value).map_err(|_| ResponseError::Malformed)?,
        );
    }
    let status = status.unwrap_or_else(|| {
        if headers.contains_key(http::header::LOCATION) {
            StatusCode::FOUND
        } else {
            StatusCode::OK
        }
    });
    Ok(CgiHead {
        status,
        headers,
        body_prefix: bytes.slice(head_len..),
    })
}

/// Return the application status from a successful END_REQUEST record.
pub fn parse_end_request(content: &[u8]) -> Result<u32, ResponseError> {
    if content.len() != 8 || content[4] != 0 || content[5..].iter().any(|byte| *byte != 0) {
        return Err(ResponseError::IncompleteRequest);
    }
    Ok(u32::from_be_bytes(content[..4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_headers_duplicates_and_body_prefix_parse() {
        let parsed = parse_cgi_head(
            Bytes::from_static(b"Status: 201 Created\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody"),
            1024,
            8,
        )
        .unwrap();
        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.headers.get_all("set-cookie").iter().count(), 2);
        assert_eq!(parsed.body_prefix, "body");
    }

    #[test]
    fn location_defaults_to_redirect_and_plain_response_to_ok() {
        assert_eq!(
            parse_cgi_head(Bytes::from_static(b"Location: /next\r\n\r\n"), 100, 2)
                .unwrap()
                .status,
            StatusCode::FOUND
        );
        assert_eq!(
            parse_cgi_head(
                Bytes::from_static(b"Content-Type: text/plain\r\n\r\n"),
                100,
                2
            )
            .unwrap()
            .status,
            StatusCode::OK
        );
    }

    #[test]
    fn malformed_folded_hop_by_hop_duplicate_status_and_bounds_reject() {
        for value in [
            b" Bad: fold\r\n\r\n".as_slice(),
            b"Connection: close\r\n\r\n",
            b"Status: 200 OK\r\nStatus: 201 X\r\n\r\n",
            b"Broken\r\n\r\n",
            b"X: bad\nY: ok\r\n\r\n",
        ] {
            assert_eq!(
                parse_cgi_head(Bytes::copy_from_slice(value), 1024, 8).unwrap_err(),
                ResponseError::Malformed
            );
        }
        assert_eq!(
            parse_cgi_head(Bytes::from_static(b"A: 1\r\nB: 2\r\n\r\n"), 1024, 1).unwrap_err(),
            ResponseError::TooLarge
        );
    }

    #[test]
    fn end_request_requires_complete_protocol_status_and_reserved_bytes() {
        assert_eq!(parse_end_request(&[0, 0, 0, 7, 0, 0, 0, 0]), Ok(7));
        assert_eq!(
            parse_end_request(&[0, 0, 0, 0, 2, 0, 0, 0]),
            Err(ResponseError::IncompleteRequest)
        );
    }
}
