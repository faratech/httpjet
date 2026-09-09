//! Bounded, one-request control protocol. Never connected to public serving.
use crate::admin_auth::AuthToken;
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_HEAD: usize = 8192;
pub(crate) const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Revision,
    Validate,
    Publish,
}

pub(crate) struct Request {
    pub(crate) operation: Operation,
    pub(crate) revision: Option<String>,
    pub(crate) body: Vec<u8>,
}

struct Head {
    operation: Operation,
    revision: Option<String>,
    length: usize,
}

fn single<'a>(headers: &[httparse::Header<'a>], name: &str) -> Result<Option<&'a [u8]>, u16> {
    let mut found = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = found.next().map(|h| h.value);
    if found.next().is_some() {
        return Err(400);
    }
    Ok(value)
}

fn revision(value: &[u8]) -> Result<String, u16> {
    let text = std::str::from_utf8(value).map_err(|_| 400_u16)?;
    let inner = text
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(400_u16)?;
    let (incarnation, number) = inner.split_once('-').ok_or(400_u16)?;
    if incarnation.len() != 32
        || !incarnation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || number.is_empty()
        || number.starts_with('0')
        || !number.bytes().all(|b| b.is_ascii_digit())
        || number.parse::<u64>().is_err()
    {
        return Err(400);
    }
    Ok(inner.to_owned())
}

fn parse(bytes: &[u8], local: SocketAddr, token: &AuthToken) -> Result<Head, u16> {
    if bytes.len() > MAX_HEAD {
        return Err(431);
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(n)) if n == bytes.len() => {}
        _ => return Err(400),
    }
    if request.version != Some(1) || !local.ip().is_loopback() {
        return Err(400);
    }
    let host = single(request.headers, "host")?.ok_or(400_u16)?;
    let host = std::str::from_utf8(host).map_err(|_| 400_u16)?;
    if host != format!("localhost:{}", local.port())
        && host.parse::<SocketAddr>().ok() != Some(local)
    {
        return Err(400);
    }
    if request.headers.iter().any(|h| {
        [
            "origin",
            "transfer-encoding",
            "content-encoding",
            "expect",
            "upgrade",
            "trailer",
        ]
        .iter()
        .any(|name| h.name.eq_ignore_ascii_case(name))
    }) {
        return Err(400);
    }
    // Reject before waiting for or allocating the submitted configuration body.
    if !token.authenticate(request.headers) {
        return Err(401);
    }
    let operation = match (request.method, request.path) {
        (Some("GET"), Some("/v1/revision")) => Operation::Revision,
        (Some("POST"), Some("/v1/config/validate")) => Operation::Validate,
        (Some("PUT"), Some("/v1/config")) => Operation::Publish,
        (_, Some("/v1/revision" | "/v1/config/validate" | "/v1/config")) => return Err(405),
        _ => return Err(404),
    };
    let length = single(request.headers, "content-length")?;
    let expected = single(request.headers, "if-match")?;
    if operation == Operation::Revision {
        if length.is_some() || expected.is_some() {
            return Err(400);
        }
        return Ok(Head {
            operation,
            revision: None,
            length: 0,
        });
    }
    let expected = revision(expected.ok_or(428_u16)?)?;
    if single(request.headers, "content-type")? != Some(b"application/json".as_slice()) {
        return Err(415);
    }
    let length = length.ok_or(411_u16)?;
    if length.is_empty() || !length.iter().all(u8::is_ascii_digit) {
        return Err(400);
    }
    let length = std::str::from_utf8(length)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(413_u16)?;
    if length == 0 {
        return Err(400);
    }
    if length > MAX_BODY {
        return Err(413);
    }
    Ok(Head {
        operation,
        revision: Some(expected),
        length,
    })
}

/// Caller admits a bounded number of connections and closes after one response.
/// Extra/pipelined requests are never processed. The deadline covers header and
/// body together, so a slow sender cannot reset its budget one byte at a time.
pub(crate) async fn receive<S: AsyncRead + Unpin>(
    stream: &mut S,
    local: SocketAddr,
    token: &AuthToken,
) -> Result<Request, u16> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::with_capacity(1024);
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() == MAX_HEAD {
                return Err(431);
            }
            let byte = stream.read_u8().await.map_err(|_| 400_u16)?;
            bytes.push(byte);
        }
        let head = parse(&bytes, local, token)?;
        let mut body = vec![0; head.length];
        stream.read_exact(&mut body).await.map_err(|_| 400_u16)?;
        Ok(Request {
            operation: head.operation,
            revision: head.revision,
            body,
        })
    })
    .await
    .map_err(|_| 408_u16)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const REV: &str = "0123456789abcdef0123456789abcdef-1";
    fn local() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }
    fn head(method: &str, path: &str, extras: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {TOKEN}\r\n{extras}\r\n",
            local()
        )
    }
    fn upload(extra: &str) -> String {
        head(
            "PUT",
            "/v1/config",
            &format!(
                "If-Match: \"{REV}\"\r\nContent-Type: application/json\r\nContent-Length: 2\r\n{extra}"
            ),
        )
    }
    #[test]
    fn framing_authentication_preconditions_and_origin_boundaries() {
        let auth = AuthToken::fixture(TOKEN.as_bytes());
        let valid = upload("");
        let parsed = parse(valid.as_bytes(), local(), &auth).unwrap();
        assert_eq!(parsed.operation, Operation::Publish);
        assert_eq!(parsed.revision.as_deref(), Some(REV));
        for extra in [
            "Origin: null\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Encoding: gzip\r\n",
            "Expect: 100-continue\r\n",
            "Content-Length: 2\r\n",
            "Host: localhost:12345\r\n",
            "If-Match: *\r\n",
        ] {
            assert!(
                parse(upload(extra).as_bytes(), local(), &auth).is_err(),
                "{extra}"
            );
        }
        for (bad, expected) in [
            (
                valid.replace(&format!("Authorization: Bearer {TOKEN}\r\n"), ""),
                401,
            ),
            (upload(&format!("Authorization: Bearer {TOKEN}\r\n")), 401),
            (valid.replace(&format!("If-Match: \"{REV}\"\r\n"), ""), 428),
            (
                valid.replace("Content-Length: 2", "Content-Length: 1048577"),
                413,
            ),
            (
                valid.replace("Content-Length: 2", "Content-Length: +2"),
                400,
            ),
            (valid.replace("application/json", "text/plain"), 415),
            (valid.replace("127.0.0.1:12345", "example.com"), 400),
            (valid.replace("127.0.0.1:12345", "127.0.0.1:80"), 400),
            (valid.replace("/v1/config", "/v1/config?token=x"), 404),
            (format!("{valid}GET / HTTP/1.1\r\n\r\n"), 400),
        ] {
            assert_eq!(parse(bad.as_bytes(), local(), &auth).err(), Some(expected));
        }
        for bad in [
            "*",
            "W/\"x\"",
            "\"0123456789abcdef0123456789abcdef-01\"",
            "\"0123456789abcdef0123456789abcdef-18446744073709551616\"",
        ] {
            assert!(revision(bad.as_bytes()).is_err());
        }
    }
    #[tokio::test]
    async fn bounded_reader_authenticates_before_body_and_reads_exact_length() {
        let auth = AuthToken::fixture(TOKEN.as_bytes());
        let (mut client, mut server) = tokio::io::duplex(4096);
        let unauthorized = upload("").replace(TOKEN, &"a".repeat(64));
        client.write_all(unauthorized.as_bytes()).await.unwrap();
        // Keep the sender open without a body; authentication must not wait.
        let result = tokio::time::timeout(
            Duration::from_millis(250),
            receive(&mut server, local(), &auth),
        )
        .await
        .unwrap();
        assert_eq!(result.err(), Some(401));
        let mut valid = format!("{}{{}}ignored-pipeline", upload("")).into_bytes();
        let request = receive(&mut valid.as_slice(), local(), &auth)
            .await
            .unwrap();
        assert_eq!(request.body, b"{}");
        valid.clear();
        assert_eq!(
            receive(&mut valid.as_slice(), local(), &auth).await.err(),
            Some(400)
        );
    }

    #[tokio::test]
    async fn incomplete_header_and_body_share_a_bounded_deadline() {
        let auth = AuthToken::fixture(TOKEN.as_bytes());
        let (mut header_client, mut header_server) = tokio::io::duplex(4096);
        let (mut body_client, mut body_server) = tokio::io::duplex(4096);
        header_client
            .write_all(b"PUT /v1/config HTTP/1.1\r\n")
            .await
            .unwrap();
        body_client.write_all(upload("").as_bytes()).await.unwrap();
        body_client.write_all(b"{").await.unwrap();
        let (header, body) = tokio::join!(
            receive(&mut header_server, local(), &auth),
            receive(&mut body_server, local(), &auth),
        );
        assert_eq!(header.err(), Some(408));
        assert_eq!(body.err(), Some(408));
        // The clients remained connected; these are deadlines, not EOF failures.
        drop((header_client, body_client));
        let oversized = vec![b'a'; MAX_HEAD];
        assert_eq!(
            receive(&mut oversized.as_slice(), local(), &auth)
                .await
                .err(),
            Some(431)
        );
    }
}
