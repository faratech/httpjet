use hj_core::config::*;
use hj_core::{Proto, ReqCtx};
use hj_proxy::{Proxy, ProxyTarget};
use http_body_util::{BodyExt, Full};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use std::time::Duration;
fn ctx() -> ReqCtx {
    let server = ServerConfig {
        server_root: Default::default(),
        server_name: String::new(),
        user: String::new(),
        group: String::new(),
        index_files: vec![],
        tuning: Default::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: Default::default(),
        vhost_order: vec![],
        mime: Default::default(),
    };
    ReqCtx {
        server: Arc::new(server),
        vhost_name: String::new(),
        vhost: Arc::new(hj_core::config::VHostConfig::default()),
        peer_ip: "127.0.0.1".parse().unwrap(),
        client_ip: "127.0.0.1".parse().unwrap(),
        is_tls: false,
        peer_unix: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        env: Vec::new(),
        local_addr: "127.0.0.1:80".parse().unwrap(),
        peer_port: 40000,
        request_time: std::time::SystemTime::UNIX_EPOCH,
        request_id: hj_core::reqid::next(),
        redirect_guard: None,
        tls: None,
    }
}

fn empty_body() -> hj_core::IncomingBody {
    http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e| match e {})
        .boxed()
}

fn processor(addresses: Vec<String>, health: bool) -> ExtProcessor {
    ExtProcessor {
        name: "group".into(),
        kind: ExtKind::Proxy,
        address: ExtAddress::HostPort(addresses[0].clone()),
        extra_addresses: addresses[1..]
            .iter()
            .cloned()
            .map(ExtAddress::HostPort)
            .collect(),
        load_balance: LoadBalanceConfig {
            policy: LoadBalancePolicy::WeightedRoundRobin,
            weights: vec![2, 1],
            health_check: health.then(|| HealthCheckConfig {
                mode: "GET".into(),
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(20),
                rise: 2,
                fall: 3,
                path: "/health".into(),
                host: Some("probe.test".into()),
                expected_status: 200,
            }),
        },
        client_cert_file: None,
        client_key_file: None,
        max_conns: 10,
        init_timeout: Duration::from_secs(1),
        retry_timeout: Duration::ZERO,
        pc_keep_alive_timeout: Duration::from_secs(5),
        resp_buffer: false,
        env: vec![],
        auto_start: 0,
        path: None,
        backlog: 0,
        instances: 1,
        run_on_startup: 0,
    }
}
async fn backend(
    id: &'static str,
    h2: bool,
) -> (String, Arc<AtomicU16>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!(
        "{}://{}",
        if h2 { "h2" } else { "http" },
        listener.local_addr().unwrap()
    );
    let status = Arc::new(AtomicU16::new(200));
    let health = status.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept() => {
                    let (stream,_)=accepted.unwrap(); let health=health.clone();
                    connections.spawn(async move {
                        let service=hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                            let status=if req.uri().path()=="/health" {health.load(Ordering::Relaxed)} else {200};
                            async move {
                                Ok::<_,std::convert::Infallible>(http::Response::builder().status(status).body(Full::new(bytes::Bytes::from_static(id.as_bytes()))).unwrap())
                            }
                        });
                        let io=hyper_util::rt::TokioIo::new(stream);
                        if h2 { let _=hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io,service).await; }
                        else { let _=hyper::server::conn::http1::Builder::new().serve_connection(io,service).await; }
                    });
                },
                _=connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (address, status, task)
}
async fn request(proxy: &Proxy, target: &ProxyTarget) -> Result<String, hj_core::HandlerError> {
    let req = http::Request::builder()
        .uri("/data")
        .header("host", "app.test")
        .body(empty_body())
        .unwrap();
    let resp = proxy.forward(&ctx(), req, target, None).await?;
    match resp.into_body() {
        hj_core::Body::Stream(body) => {
            Ok(String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap())
        }
        _ => panic!("expected streaming proxy body"),
    }
}
async fn wait_health(proxy: &Proxy, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while proxy
            .pool()
            .peer_snapshots()
            .iter()
            .filter(|p| p.healthy)
            .count()
            != count
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("health transition");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_h1_and_h2_groups_distribute_two_to_one() {
    for h2 in [false, true] {
        let (a, _, sa) = backend("a", h2).await;
        let (b, _, sb) = backend("b", h2).await;
        let target = ProxyTarget::from_ext_processor(&processor(vec![a, b], false));
        assert_eq!(target.http2, h2);
        let proxy = Proxy::with_targets([target.clone()]);
        proxy.pool().activate_health_checks();
        let mut counts = [0, 0];
        for _ in 0..12 {
            let body = request(&proxy, &target).await.unwrap();
            counts[usize::from(body == "b")] += 1;
        }
        assert_eq!(counts, [8, 4]);
        proxy.pool().stop_health_checks();
        sa.abort();
        sb.abort();
        let _ = sa.await;
        let _ = sb.await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_health_excludes_down_peers_and_recovers_without_user_traffic() {
    let (a, ha, sa) = backend("a", false).await;
    let (b, hb, sb) = backend("b", false).await;
    let target = ProxyTarget::from_ext_processor(&processor(vec![a, b], true));
    let proxy = Proxy::with_targets([target.clone()]);
    assert!(matches!(
        request(&proxy, &target).await,
        Err(hj_core::HandlerError::ServiceUnavailable)
    ));
    proxy.pool().activate_health_checks();
    wait_health(&proxy, 2).await;
    ha.store(503, Ordering::Relaxed);
    wait_health(&proxy, 1).await;
    for _ in 0..5 {
        assert_eq!(request(&proxy, &target).await.unwrap(), "b");
    }
    hb.store(503, Ordering::Relaxed);
    wait_health(&proxy, 0).await;
    assert!(matches!(
        request(&proxy, &target).await,
        Err(hj_core::HandlerError::ServiceUnavailable)
    ));
    ha.store(200, Ordering::Relaxed);
    wait_health(&proxy, 1).await;
    assert_eq!(request(&proxy, &target).await.unwrap(), "a");
    proxy.pool().stop_health_checks();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let before: u64 = proxy.pool().peer_snapshots().iter().map(|p| p.probes).sum();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        before,
        proxy.pool().peer_snapshots().iter().map(|p| p.probes).sum()
    );
    sa.abort();
    sb.abort();
    let _ = sa.await;
    let _ = sb.await;
}
