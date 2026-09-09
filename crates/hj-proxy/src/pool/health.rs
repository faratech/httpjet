use super::*;
use hj_core::config::{HealthCheckConfig, LoadBalanceConfig};
use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncWrite};

pub(super) struct HealthState {
    pub(super) healthy: bool,
    pub(super) probes: u64,
    pub(super) transitions: u64,
    successes: u32,
    failures: u32,
}
impl HealthState {
    pub(super) fn new(healthy: bool) -> Self {
        Self {
            healthy,
            probes: 0,
            transitions: 0,
            successes: 0,
            failures: 0,
        }
    }
    fn record(&mut self, ok: bool, config: &HealthCheckConfig) {
        self.probes += 1;
        let before = self.healthy;
        if ok {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            if self.successes >= config.rise {
                self.healthy = true;
            }
        } else {
            self.successes = 0;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= config.fall {
                self.healthy = false;
            }
        }
        if before != self.healthy {
            self.transitions += 1;
        }
    }
}
trait ProbeIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProbeIo for T {}
struct Driver(tokio::task::AbortHandle);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn probe(up: &Upstream, config: &HealthCheckConfig) -> bool {
    tokio::time::timeout(config.timeout, async {
        let io: Box<dyn ProbeIo> = match &up.transport {
            TargetTransport::Tcp(address) => {
                let stream = TcpStream::connect(address).await.ok()?;
                if config.mode == "connect" {
                    return Some(true);
                }
                if let Some(tls) = &up.tls_config {
                    let tls = tls.as_ref().ok()?.clone();
                    let server_name = up.tls_server_name.clone()?;
                    let stream = TlsConnector::from(tls)
                        .connect(server_name, stream)
                        .await
                        .ok()?;
                    if up.requires_h2
                        && require_h2_alpn(&up.authority, stream.get_ref().1.alpn_protocol())
                            .is_err()
                    {
                        return None;
                    }
                    Box::new(stream)
                } else {
                    Box::new(stream)
                }
            }
            TargetTransport::Uds(path) => {
                let stream = tokio::net::UnixStream::connect(path).await.ok()?;
                if config.mode == "connect" {
                    return Some(true);
                }
                Box::new(stream)
            }
        };
        let io = hyper_util::rt::TokioIo::new(io);
        let (mut sender, _driver) = if up.requires_h2 {
            let (s, c) =
                hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .max_header_list_size(16 * 1024)
                    .handshake::<_, OutBody>(io)
                    .await
                    .ok()?;
            let task = tokio::spawn(c);
            (AnySender::H2(s), Driver(task.abort_handle()))
        } else {
            let (s, c) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(16 * 1024)
                .handshake::<_, OutBody>(io)
                .await
                .ok()?;
            let task = tokio::spawn(c);
            (AnySender::H1(s), Driver(task.abort_handle()))
        };
        sender.ready().await.ok()?;
        let host = config.host.as_deref().unwrap_or(&up.authority);
        let uri = if up.requires_h2 {
            format!(
                "{}://{host}{}",
                if up.tls_config.is_some() {
                    "https"
                } else {
                    "http"
                },
                config.path
            )
        } else {
            config.path.clone()
        };
        let request = http::Request::builder()
            .method(config.mode.as_str())
            .uri(uri)
            .header(http::header::HOST, host)
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .ok()?;
        let response = sender.send_request(request).await.ok()?;
        Some(response.status().as_u16() == config.expected_status)
        // The response and driver are dropped here; probe bodies are never drained.
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

impl UpstreamPool {
    pub(crate) fn prepare_groups(
        &self,
        targets: impl IntoIterator<Item = ProxyTarget>,
        max: u32,
        keep: Duration,
        connect: Duration,
    ) {
        for target in targets {
            if target.name.is_some() && target.load_balance != LoadBalanceConfig::default() {
                self.group(&target, max, keep, connect);
            }
        }
    }
    pub fn stop_health_checks(&self) {
        for task in self.health_tasks.lock().drain(..) {
            task.abort();
        }
    }
    /// Call only after the candidate configuration has been published.
    pub fn activate_health_checks(&self) {
        self.stop_health_checks();
        let groups: Vec<_> = self.groups.lock().values().cloned().collect();
        *self.published_groups.lock() = Some(groups.clone());
        static LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let limit = LIMIT.get_or_init(|| Arc::new(Semaphore::new(16))).clone();
        for group in groups {
            let Some(config) = group.config.health_check.clone() else {
                continue;
            };
            for peer in &group.peers {
                let peer = peer.clone();
                let config = config.clone();
                let limit = limit.clone();
                let task = tokio::spawn(async move {
                    let mut timer = tokio::time::interval(config.interval);
                    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        timer.tick().await;
                        let Ok(permit) = limit.acquire().await else {
                            break;
                        };
                        let ok = probe(&peer.upstream, &config).await;
                        drop(permit);
                        let mut state = peer.health.lock();
                        state.record(ok, &config);
                        if ok && state.healthy {
                            peer.upstream.note_dial_success();
                        }
                    }
                });
                self.health_tasks.lock().push(task.abort_handle());
            }
        }
    }
}
impl Drop for UpstreamPool {
    fn drop(&mut self) {
        self.stop_health_checks();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> HealthCheckConfig {
        HealthCheckConfig {
            mode: "connect".into(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            rise: 2,
            fall: 3,
            path: "/".into(),
            host: None,
            expected_status: 200,
        }
    }
    #[test]
    fn thresholds_and_reset() {
        let mut h = HealthState::new(false);
        let c = config();
        h.record(true, &c);
        assert!(!h.healthy);
        h.record(false, &c);
        h.record(true, &c);
        assert!(!h.healthy);
        h.record(true, &c);
        assert!(h.healthy);
        for _ in 0..2 {
            h.record(false, &c);
            assert!(h.healthy);
        }
        h.record(false, &c);
        assert!(!h.healthy);
        assert_eq!(h.transitions, 2);
    }

    #[tokio::test]
    async fn http_probe_timeout_and_header_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for oversized in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target =
                ProxyTarget::parse_url(&format!("http://{}", listener.local_addr().unwrap()))
                    .unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 2048];
                let _ = socket.read(&mut buf).await;
                if oversized {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
                        "a".repeat(32768)
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                }
                let _ = socket.read(&mut buf).await;
            });
            let up = Upstream::new(&target, 1, Duration::from_secs(5), Duration::from_secs(1));
            let mut c = config();
            c.mode = "HEAD".into();
            c.timeout = Duration::from_millis(100);
            assert!(!probe(&up, &c).await);
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn tls_health_requires_trust_and_h2_alpn() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        for (trusted, h2_alpn, expected) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
        ] {
            let generated =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert = generated.cert.der().clone();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            ));
            let mut tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap();
            if h2_alpn {
                tls.alpn_protocols = vec![b"h2".to_vec()];
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target =
                ProxyTarget::parse_url(&format!("h2s://{}", listener.local_addr().unwrap()))
                    .unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                if let Ok(tls) = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                    .accept(tcp)
                    .await
                {
                    let service = hyper::service::service_fn(|_| async {
                        Ok::<_, std::convert::Infallible>(http::Response::new(
                            http_body_util::Empty::<bytes::Bytes>::new(),
                        ))
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
                }
            });
            let mut roots = rustls::RootCertStore::empty();
            if trusted {
                roots.add(cert).unwrap();
            }
            let client = with_upstream_alpn(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
                true,
            );
            let mut up = Upstream::new(&target, 1, Duration::from_secs(5), Duration::from_secs(1));
            Arc::get_mut(&mut up).unwrap().tls_config = Some(Ok(Arc::new(client)));
            Arc::get_mut(&mut up).unwrap().tls_server_name =
                Some(ServerName::try_from("localhost").unwrap());
            let mut c = config();
            c.mode = "GET".into();
            assert_eq!(probe(&up, &c).await, expected);
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn http_probe_does_not_follow_redirect_or_drain_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target =
            ProxyTarget::parse_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 16384);
            }
            let request = String::from_utf8(request).unwrap().to_lowercase();
            assert!(request.starts_with("get /health?ready=1 http/1.1"));
            assert!(request.contains("host: probe.test"));
            assert!(!request.contains("cookie:"));
            assert!(!request.contains("authorization:"));
            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 999999999\r\n\r\n").await.unwrap();
            let mut buf = [0; 16];
            let _ = socket.read(&mut buf).await;
        });
        let up = Upstream::new(&target, 1, Duration::from_secs(5), Duration::from_secs(1));
        let mut c = config();
        c.mode = "GET".into();
        c.path = "/health?ready=1".into();
        c.host = Some("probe.test".into());
        assert!(!probe(&up, &c).await);
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn rejected_candidate_and_published_metrics_generation() {
        let mut t = ProxyTarget::parse_url("http://127.0.0.1:1")
            .unwrap()
            .in_scope("server");
        t.name = Some("test".into());
        t.load_balance.policy = hj_core::config::LoadBalancePolicy::WeightedRoundRobin;
        let old = crate::Proxy::with_targets([t.clone()]);
        old.pool().activate_health_checks();
        assert_eq!(old.pool().peer_snapshots().len(), 1);
        let candidate = old.next_generation([]);
        assert_eq!(old.pool().peer_snapshots().len(), 1);
        assert!(candidate.pool().health_tasks.lock().is_empty());
        candidate.pool().activate_health_checks();
        assert!(old.pool().peer_snapshots().is_empty());
    }
    #[tokio::test]
    async fn no_probes_before_activation_and_retirement_stops_them() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut t =
            ProxyTarget::parse_url(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        t.name = Some("health".into());
        let mut c = config();
        c.rise = 1;
        t.load_balance.health_check = Some(c);
        let p = UpstreamPool::new();
        p.prepare_groups(
            [t.clone()],
            10,
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        assert!(
            p.select(&t, 10, Duration::from_secs(5), Duration::from_secs(1))
                .is_err()
        );
        assert!(p.health_tasks.lock().is_empty());
        p.activate_health_checks();
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !p.peer_snapshots()[0].healthy {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        p.stop_health_checks();
        assert!(p.health_tasks.lock().is_empty());
    }
}
