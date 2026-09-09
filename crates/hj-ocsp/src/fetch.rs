use crate::{Error, MAX_RESPONSE};
use base64::Engine;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

/// Explicit responder destination, never inferred from untrusted response data.
#[derive(Clone)]
pub struct Endpoint {
    url: reqwest::Url,
    loopback_test: bool,
}
impl Endpoint {
    pub fn new(url: &str, loopback_test: bool) -> Result<Self, Error> {
        if url.len() > 2048 {
            return Err(Error);
        }
        let url = reqwest::Url::parse(url).map_err(|_| Error)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port_or_known_default().is_none_or(|p| p == 0)
        {
            return Err(Error);
        }
        let host = url.host_str().ok_or(Error)?.trim_matches(['[', ']']);
        let literal = host.parse::<IpAddr>().ok();
        if loopback_test {
            // Test mode permits literal loopback ONLY, never private-network access.
            if !literal.is_some_and(|ip| ip.is_loopback()) {
                return Err(Error);
            }
        } else if literal.is_some_and(|ip| !public(ip)) {
            return Err(Error);
        }
        Ok(Self { url, loopback_test })
    }
    pub async fn fetch(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if request.is_empty() || request.len() > 4096 {
            return Err(Error);
        }
        tokio::time::timeout(Duration::from_secs(10), self.fetch_inner(request))
            .await
            .map_err(|_| Error)?
    }
    async fn fetch_inner(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let host = self.url.host_str().ok_or(Error)?.trim_matches(['[', ']']);
        let port = self.url.port_or_known_default().ok_or(Error)?;
        let addresses: Vec<SocketAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| Error)?
                .take(17)
                .collect(),
        };
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses.iter().any(|a| {
                if self.loopback_test {
                    !a.ip().is_loopback()
                } else {
                    !public(a.ip())
                }
            })
        {
            return Err(Error);
        }
        // Resolve once, verify every address, and pin the result for this fetch.
        // Hostname/SNI verification still uses the configured host, not the IP.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &addresses)
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| Error)?;
        let outgoing = match self.get_url(request)? {
            Some(url) => client.get(url),
            None => client
                .post(self.url.clone())
                .header("content-type", "application/ocsp-request")
                .body(request.to_vec()),
        };
        let mut response = outgoing
            .header("accept", "application/ocsp-response")
            .send()
            .await
            .map_err(|_| Error)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE as u64)
            || response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .is_none_or(|h| {
                    !h.split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .eq_ignore_ascii_case("application/ocsp-response")
                })
            || response.headers().contains_key("content-encoding")
        {
            return Err(Error);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error)? {
            if chunk.len() > MAX_RESPONSE - bytes.len() {
                return Err(Error);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Err(Error);
        }
        Ok(bytes)
    }

    // RFC 6960 A.1.1 / lightweight transport profile: measure the complete
    // percent-encoded URL, not merely the DER or base64 payload.
    fn get_url(&self, request: &[u8]) -> Result<Option<reqwest::Url>, Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(request);
        let mut url = self.url.as_str().trim_end_matches('/').to_owned();
        url.push('/');
        for byte in encoded.bytes() {
            match byte {
                b'+' => url.push_str("%2B"),
                b'/' => url.push_str("%2F"),
                b'=' => url.push_str("%3D"),
                _ => url.push(char::from(byte)),
            }
        }
        if url.len() > 255 {
            return Ok(None);
        }
        Ok(Some(reqwest::Url::parse(&url).map_err(|_| Error)?))
    }
}

// Conservative public-unicast allowlist. Special-use and translation ranges
// are excluded even where some subranges have narrow global exceptions.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => public_v6(ip),
    }
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && ((18..=19).contains(&b) || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}
fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    (0x2000..=0x3fff).contains(&s[0])
        && s[0] != 0x2002
        && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
        && !(s[0] == 0x3fff && s[1] <= 0xfff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    #[test]
    fn get_encoding_and_complete_url_boundary() {
        let endpoint = Endpoint::new("http://example.com/ocsp/", false).unwrap();
        assert_eq!(
            endpoint.get_url(&[0xfb, 0xff]).unwrap().unwrap().as_str(),
            "http://example.com/ocsp/%2B%2F8%3D"
        );
        // One byte encodes to AA%3D%3D: eight URL bytes, plus separator.
        for (length, get) in [(246, true), (247, false)] {
            let mut base = "http://example.com/".to_owned();
            base.extend(std::iter::repeat_n('a', length - base.len()));
            let endpoint = Endpoint::new(&base, false).unwrap();
            let result = endpoint.get_url(&[0]).unwrap();
            assert_eq!(result.is_some(), get);
            if let Some(url) = result {
                assert_eq!(url.as_str().len(), 255);
            }
        }
    }
    #[test]
    fn endpoints_and_resolved_addresses_are_scoped() {
        for bad in [
            "file:///etc/passwd",
            "http://u:p@example.com/",
            "http://127.1/",
            "http://2130706433/",
            "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/",
            "http://example.com/?token=x",
        ] {
            assert!(Endpoint::new(bad, false).is_err(), "{bad}");
        }
        assert!(Endpoint::new("http://127.0.0.1:1234/status", true).is_ok());
        assert!(Endpoint::new("http://localhost/status", true).is_err());
        assert!(Endpoint::new("https://ocsp.example.com/", false).is_ok());
        for bad in [
            "100.64.0.1",
            "198.19.1.1",
            "2001:db8::1",
            "2002::1",
            "fc00::1",
            "fe80::1",
            "3fff::1",
        ] {
            assert!(!public(bad.parse().unwrap()));
        }
        for good in ["8.8.8.8", "2606:4700::1111"] {
            assert!(public(good.parse().unwrap()));
        }
    }
    #[tokio::test]
    async fn wire_uses_encoded_get_or_binary_post() {
        for request in [vec![0xfb, 0xff], vec![42; 256]] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Endpoint::new(
                &format!("http://{}/ocsp", listener.local_addr().unwrap()),
                true,
            )
            .unwrap();
            let expected = request.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                let mut byte = [0; 1];
                while !received.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).await.unwrap();
                    received.push(byte[0]);
                    assert!(received.len() < 4096);
                }
                let header = String::from_utf8(received).unwrap().to_ascii_lowercase();
                if expected.len() == 2 {
                    assert!(header.starts_with("get /ocsp/%2b%2f8%3d http/1.1\r\n"));
                    assert!(!header.contains("content-type:"));
                } else {
                    assert!(header.starts_with("post /ocsp http/1.1\r\n"));
                    assert!(header.contains("content-type: application/ocsp-request\r\n"));
                    assert!(header.contains("content-length: 256\r\n"));
                    let mut body = vec![0; expected.len()];
                    stream.read_exact(&mut body).await.unwrap();
                    assert_eq!(body, expected);
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 3\r\n\r\nabc").await.unwrap();
            });
            assert_eq!(endpoint.fetch(&request).await.unwrap(), b"abc");
            server.await.unwrap();
        }
    }
    #[tokio::test]
    async fn bounded_fetch_rejects_redirects_encodings_and_oversized_bodies() {
        for (reply, success) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 3\r\n\r\nabc",
                true,
            ),
            (
                "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: 65537\r\n\r\n",
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc",
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nabc",
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Endpoint::new(
                &format!("http://{}/ocsp", listener.local_addr().unwrap()),
                true,
            )
            .unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                let _ = stream.read(&mut buffer).await.unwrap();
                stream.write_all(reply.as_bytes()).await.unwrap();
            });
            let result = endpoint.fetch(b"fixture-request").await;
            assert_eq!(result.is_ok(), success);
            if success {
                assert_eq!(result.unwrap(), b"abc");
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn chunked_limit_and_total_deadline_apply_without_content_length() {
        for oversized in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = Endpoint::new(
                &format!("http://{}/ocsp", listener.local_addr().unwrap()),
                true,
            )
            .unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                assert!(stream.read(&mut buffer).await.unwrap() > 0);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                if oversized {
                    let body = format!("10001\r\n{}\r\n0\r\n\r\n", "x".repeat(MAX_RESPONSE + 1));
                    let _ = stream.write_all(body.as_bytes()).await;
                } else {
                    // Wait for the client's deadline to close the connection;
                    // no arbitrary sleep and no task left behind by this test.
                    while stream.read(&mut buffer).await.unwrap_or(0) != 0 {}
                }
            });
            let start = Instant::now();
            assert!(
                tokio::time::timeout(Duration::from_secs(12), endpoint.fetch(b"fixture-request"))
                    .await
                    .unwrap()
                    .is_err()
            );
            if !oversized {
                assert!(start.elapsed() >= Duration::from_secs(9));
            }
            server.await.unwrap();
        }
    }
}
