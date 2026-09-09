//! Restricted HTTP adapter for instant-acme. Never returns upstream text in errors.
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};

use crate::Directory;

const MAX_BODY: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct BoundedHttp {
    client: reqwest::Client,
    directory: Directory,
    retry_after: Arc<AtomicU64>,
}

impl BoundedHttp {
    pub(crate) fn new(directory: Directory, test_root: Option<&[u8]>) -> Result<Self, Error> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(1)
            .user_agent("httpjet-acme/1");
        if let Some(pem) = test_root {
            if pem.len() > 64 * 1024 {
                return Err(Error::Str("ACME trust root exceeds limit"));
            }
            let root = reqwest::Certificate::from_pem(pem)
                .map_err(|_| Error::Str("invalid ACME trust root"))?;
            builder = builder.tls_certs_only([root]);
        }
        Ok(Self {
            client: builder
                .build()
                .map_err(|_| Error::Str("ACME HTTP initialization failed"))?,
            directory,
            retry_after: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(crate) fn permits(&self, uri: &Uri) -> bool {
        let base = self.directory.uri();
        let default_port = if base.scheme_str() == Some("https") {
            443
        } else {
            80
        };
        uri.to_string().len() <= 2048
            && uri.scheme_str() == base.scheme_str()
            && uri
                .host()
                .zip(base.host())
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
            && uri.port_u16().unwrap_or(default_port) == base.port_u16().unwrap_or(default_port)
            && uri.authority().is_some_and(|a| {
                !a.as_str().contains('@')
                    && !(a.as_str().contains(':')
                        && a.port_u16().is_none()
                        && !a.as_str().ends_with(']'))
            })
    }

    pub(crate) fn retry_after(&self) -> u64 {
        self.retry_after.load(Ordering::Relaxed)
    }
}

impl HttpClient for BoundedHttp {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let this = self.clone();
        Box::pin(async move {
            if !this.permits(req.uri())
                || !matches!(*req.method(), Method::GET | Method::HEAD | Method::POST)
            {
                return Err(Error::Str(
                    "ACME request outside permitted origin or method",
                ));
            }
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            if body.len() > MAX_BODY {
                return Err(Error::Str("ACME request exceeds limit"));
            }
            let mut response = this
                .client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| Error::Str("ACME HTTP request failed"))?;
            if response.status().is_redirection() {
                return Err(Error::Str("ACME redirects are prohibited"));
            }
            if let Some(value) = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
            {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let until = value
                    .parse::<u64>()
                    .ok()
                    .map(|seconds| now.saturating_add(seconds))
                    .or_else(|| {
                        httpdate::parse_http_date(value)
                            .ok()?
                            .duration_since(UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs())
                    });
                if let Some(until) = until {
                    this.retry_after.fetch_max(until, Ordering::Relaxed);
                }
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_BODY as u64)
            {
                return Err(Error::Str("ACME response exceeds limit"));
            }
            let mut output = http::Response::builder().status(response.status());
            *output.headers_mut().unwrap() = response.headers().clone();
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| Error::Str("ACME response failed"))?
            {
                if chunk.len() > MAX_BODY - bytes.len() {
                    return Err(Error::Str("ACME response exceeds limit"));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(BytesResponse::from(
                output.body(Full::new(Bytes::from(bytes)))?,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_origin_is_not_a_redirect_allowlist() {
        let client = BoundedHttp::new(
            Directory::parse("https://ca.test/directory", false).unwrap(),
            None,
        )
        .unwrap();
        for good in ["https://ca.test/new-account", "https://CA.test:443/order/1"] {
            assert!(client.permits(&good.parse().unwrap()));
        }
        for bad in [
            "http://ca.test/order",
            "https://ca.test:444/order",
            "https://ca.test.evil/order",
            "https://user@ca.test/order",
            "/order",
        ] {
            assert!(!client.permits(&bad.parse().unwrap()));
        }
    }

    #[tokio::test]
    async fn bounds_chunked_responses_and_rejects_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for oversized in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                assert!(socket.read(&mut buffer).await.unwrap() > 0);
                if oversized {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .await
                        .unwrap();
                    let chunk = vec![b'x'; 65536];
                    for _ in 0..17 {
                        if socket.write_all(b"10000\r\n").await.is_err() {
                            break;
                        }
                        if socket.write_all(&chunk).await.is_err() {
                            break;
                        }
                        if socket.write_all(b"\r\n").await.is_err() {
                            break;
                        }
                    }
                } else {
                    socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/secret\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                }
            });
            let directory = Directory::parse(&format!("http://{address}/dir"), true).unwrap();
            let client = BoundedHttp::new(directory.clone(), None).unwrap();
            let result = client
                .request(
                    Request::builder()
                        .uri(directory.uri())
                        .body(BodyWrapper::default())
                        .unwrap(),
                )
                .await;
            assert!(matches!(
                result,
                Err(Error::Str("ACME response exceeds limit"))
                    | Err(Error::Str("ACME redirects are prohibited"))
            ));
            server.await.unwrap();
        }
    }
}
