//! Stopping the standalone lsphp pool (the `httpjet lsphp` SIGTERM path) must end
//! when the in-flight requests do, not at the 20 s graceful deadline. Under steady
//! traffic a web-side external pool keeps reusing its keep-alive connections, so
//! the old workers never idle long enough to notice their dead master and the
//! drain ran to the deadline and SIGKILLed whatever was mid-request. The stop now
//! publishes a retirement epoch first: the web pool drops its idle sockets,
//! re-pools nothing, and retires each worker after its response.
//!
//! The test stands in for systemd (it owns the listening socket) and for a
//! `systemctl restart`: the next supervisor adopts the same socket, serves the
//! dials queued during the stop, and supersedes the retirement epoch.
//!
//! `#[ignore]`: spawns the real lsphp on a temp socket; run manually on an R&D box:
//!   cargo test -p hj-lsapi --test stop_retires_pooled_workers -- --ignored --nocapture

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};

use hj_core::config::{ServerConfig, Tuning, VHostConfig};
use hj_core::{Handler, Proto, ReqCtx};
use hj_lsapi::{ExternalGenerationWriter, Lsapi, LsapiRegistry, SupervisorConfig};

const LSPHP: &str = "/usr/local/lsws/lsphp8/bin/lsphp";
const STOP_BUDGET: Duration = Duration::from_secs(10);
const TRAFFIC_LOOPS: usize = 3;

fn php_config(command: PathBuf) -> hj_core::config::PhpConfig {
    hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command,
        suffixes: vec!["php".into()],
        env: vec![],
        max_conns: 4,
        init_timeout: Duration::from_secs(10),
        retry_timeout: Duration::from_secs(0),
        pc_keep_alive_timeout: Duration::from_secs(0),
        backlog: 1024,
        run_on_startup: 1,
        mem_soft_limit: None,
        mem_hard_limit: None,
        detached_mode: false,
        max_process_time: None,
        cpu_limit_secs: None,
        proc_soft_limit: None,
        proc_hard_limit: None,
        max_idle_time: None,
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    }
}

fn ctx(doc_root: &Path) -> ReqCtx {
    let server = Arc::new(ServerConfig {
        server_root: PathBuf::from("/usr/local/lsws"),
        server_name: "it".into(),
        user: "nobody".into(),
        group: "nobody".into(),
        index_files: vec!["index.php".into()],
        tuning: Tuning::default(),
        quic_enable: false,
        use_ip_in_proxy_header: 0,
        expires: Default::default(),
        cache: Default::default(),
        security: Default::default(),
        suexec: Default::default(),
        ext_processors: vec![],
        php_config: None,
        listeners: vec![],
        vhosts: BTreeMap::new(),
        vhost_order: vec![],
        mime: Default::default(),
    });
    ReqCtx {
        server,
        vhost_name: "test".into(),
        vhost: Arc::new(VHostConfig {
            doc_root: doc_root.to_path_buf(),
            ..Default::default()
        }),
        peer_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        is_tls: false,
        protocol: Proto::Http1,
        trusted_proxy: false,
        forwarding_trusted: false,
        env: vec![],
        local_addr: "127.0.0.1:8080".parse().unwrap(),
        peer_port: 0,
        peer_unix: false,
        request_time: std::time::SystemTime::now(),
        request_id: Default::default(),
        tls: None,
        redirect_guard: None,
    }
}

async fn get(handler: &Lsapi, doc_root: &Path, path: &str) -> Result<String, String> {
    let request = http::Request::builder()
        .method("GET")
        .uri(path)
        .header("Host", "localhost")
        .body(BoxBody::new(Empty::<Bytes>::new().map_err(|e| {
            let e: hj_core::BoxError = Box::new(e);
            e
        })))
        .unwrap();
    let mut ctx = ctx(doc_root);
    let response = handler
        .handle(&mut ctx, request)
        .await
        .map_err(|error| format!("{path}: dispatch failed: {error:?}"))?;
    let status = response.status();
    let bytes = match response.into_body() {
        hj_core::Body::Stream(stream) => stream
            .collect()
            .await
            .map_err(|error| format!("{path}: body failed: {error}"))?
            .to_bytes(),
        hj_core::Body::Full(bytes) => bytes,
        hj_core::Body::Empty => Bytes::new(),
        _ => return Err(format!("{path}: unexpected body kind")),
    };
    let body = String::from_utf8_lossy(&bytes).into_owned();
    if status != 200 {
        return Err(format!("{path}: status {status}: {body}"));
    }
    Ok(body)
}

/// A standalone supervisor as `httpjet lsphp` runs it: its own generation
/// writer (a fresh process mapping) and the inherited socket.
async fn start_owner(
    template: &SupervisorConfig,
    listener: &StdUnixListener,
    generation: &Path,
) -> (Arc<LsapiRegistry>, Arc<ExternalGenerationWriter>) {
    let publisher = Arc::new(ExternalGenerationWriter::open_or_create(generation).unwrap());
    let owner = LsapiRegistry::new(template.clone(), Duration::from_secs(30), None, 1 << 20);
    owner.set_listen_fd(OwnedFd::from(listener.try_clone().unwrap()));
    let hook_publisher = publisher.clone();
    assert!(
        owner.set_default_promotion_hook(Arc::new(move |core_generation, marker| {
            hook_publisher.advance_with_marker(core_generation, marker);
        }))
    );
    owner.start_default().await.expect("real lsphp pool");
    (owner, publisher)
}

/// The SIGTERM path of `httpjet lsphp`: retire, then drain.
async fn stop_owner(owner: &LsapiRegistry, publisher: &ExternalGenerationWriter) -> Duration {
    let started = Instant::now();
    publisher.retire_all();
    owner.drain_all().await.expect("graceful stop drain");
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn stop_under_traffic_retires_pooled_workers_without_waiting_out_the_grace() {
    let lsphp = PathBuf::from(LSPHP);
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }

    let base = std::env::temp_dir().join(format!("hj-lsapi-stop-retire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let doc_root = base.join("docroot");
    std::fs::create_dir_all(&doc_root).unwrap();
    std::fs::write(
        doc_root.join("fast.php"),
        b"<?php usleep(20000); echo 'FAST:', getmypid();\n",
    )
    .unwrap();
    std::fs::write(
        doc_root.join("slow.php"),
        b"<?php usleep(2000000); echo 'SLOW:', getmypid();\n",
    )
    .unwrap();
    let socket = base.join("php.sock");
    let generation = base.join("lsphp.generation");
    let listener = StdUnixListener::bind(&socket).unwrap();

    let mut template = SupervisorConfig::from_php_config(&php_config(lsphp), &socket, "", "");
    template.children = 4;
    template.normalize();

    let (first, first_publisher) = start_owner(&template, &listener, &generation).await;
    let started_generation = first_publisher.load();
    assert!(started_generation >= 1);

    let web = LsapiRegistry::new_external(template.clone(), Duration::from_secs(30), None, 1 << 20);
    assert!(web.set_external_generation_file(&generation));
    let handler = web.start_default().await.expect("external client pool");

    // Steady traffic keeps every pooled keep-alive connection busy, so no old
    // worker ever idles long enough to notice its master is gone.
    let stop_traffic = Arc::new(AtomicBool::new(false));
    let traffic: Vec<_> = (0..TRAFFIC_LOOPS)
        .map(|_| {
            let handler = handler.clone();
            let doc_root = doc_root.clone();
            let stop_traffic = stop_traffic.clone();
            tokio::spawn(async move {
                let mut served = 0u64;
                let mut errors = Vec::new();
                while !stop_traffic.load(Ordering::Acquire) {
                    match tokio::time::timeout(
                        Duration::from_secs(20),
                        get(&handler, &doc_root, "/fast.php"),
                    )
                    .await
                    {
                        Ok(Ok(body)) if body.starts_with("FAST:") => served += 1,
                        Ok(Ok(body)) => errors.push(format!("unexpected body {body}")),
                        Ok(Err(error)) => errors.push(error),
                        Err(_) => errors.push("request timed out".into()),
                    }
                }
                (served, errors)
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let slow = {
        let handler = handler.clone();
        let doc_root = doc_root.clone();
        tokio::spawn(async move { get(&handler, &doc_root, "/slow.php").await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !slow.is_finished(),
        "the slow request must still be in flight"
    );

    let stop_elapsed = stop_owner(&first, &first_publisher).await;
    let retired_generation = first_publisher.load();
    assert!(retired_generation > started_generation);
    let forced = first.default_forced_cleanup_count();
    let stopped_stats = web.default_pool_stats().expect("web pool stats");
    drop(first_publisher);

    // `systemctl restart`: the next supervisor adopts the same socket and serves
    // the dials queued while no worker was accepting.
    let (second, second_publisher) = start_owner(&template, &listener, &generation).await;
    let restarted_generation = second_publisher.load();
    assert!(
        restarted_generation > retired_generation,
        "the startup promotion must supersede the retirement epoch"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop_traffic.store(true, Ordering::Release);

    let slow_body = tokio::time::timeout(Duration::from_secs(5), slow)
        .await
        .expect("slow request finished")
        .expect("slow request task");
    let mut served = 0;
    let mut errors = Vec::new();
    for loop_task in traffic {
        let (loop_served, loop_errors) = tokio::time::timeout(Duration::from_secs(30), loop_task)
            .await
            .expect("traffic loop finished")
            .expect("traffic loop task");
        served += loop_served;
        errors.extend(loop_errors);
    }
    let restarted_stats = web.default_pool_stats().expect("web pool stats");
    eprintln!(
        "stop drained in {stop_elapsed:?}; forced={forced:?}; served={served}; errors={}; \
         at stop {stopped_stats:?}; after restart {restarted_stats:?}",
        errors.len()
    );

    let second_stop = stop_owner(&second, &second_publisher).await;
    web.drain_all()
        .await
        .expect("stop the external generation watcher");
    drop(listener);
    let _ = std::fs::remove_dir_all(&base);

    let slow_body = slow_body.expect("the in-flight request completes");
    assert!(
        slow_body.starts_with("SLOW:"),
        "in-flight body: {slow_body}"
    );
    assert!(
        errors.is_empty(),
        "no request may fail across the stop and restart: {errors:?}"
    );
    assert!(served > 0);
    assert!(
        stop_elapsed < STOP_BUDGET,
        "stop drain took {stop_elapsed:?}; pooled keep-alive workers held it to the grace deadline"
    );
    assert_eq!(forced, Some(0), "no worker may need the forced cleanup");
    assert!(
        stopped_stats.stale_idle_drops + stopped_stats.stale_checked_out_drops >= 1,
        "retirement must release the pooled keep-alive connections"
    );
    assert!(
        stopped_stats.stale_worker_retire_signals >= 1,
        "old workers are retired by the web pool after their responses"
    );
    assert_eq!(
        restarted_stats.stale_worker_retire_signals, stopped_stats.stale_worker_retire_signals,
        "the successor family's workers are never retired"
    );
    assert!(second_stop < STOP_BUDGET);
    assert_eq!(second.default_forced_cleanup_count(), Some(0));
}
