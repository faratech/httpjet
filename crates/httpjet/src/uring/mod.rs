//! Pure-io_uring (monoio) thread-per-core transport.
//!
//! `serve` starts one monoio runtime per inherited/self-bound `SO_REUSEPORT` TCP listener. Plain
//! H1/h2c and TLS H1/H2 are framed on monoio and dispatch each request through a
//! bridge into the ambient tokio runtime, where the normal httpjet pipeline,
//! LSAPI/proxy/page-cache state, metrics, and reload logic live.
//!
//! Historical smoke entrypoints (`HJ_URING_*`) remain for isolated tests. Production
//! HTTP/3 is the quinn-proto driver in this module.

pub(crate) mod bridge;
pub(crate) mod codec;
pub(crate) mod directio;
pub(crate) mod h3;
#[cfg(feature = "ktls")]
pub(crate) mod ktls;

use std::io;
use std::net::SocketAddr;

use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use socket2::{Domain, Protocol, Socket, Type};

use crate::state::ServerState;
use bridge::{Bridge, BridgeCtx};
use codec::{
    BodyFraming, ChunkStep, ChunkedDecoder, MAX_REQUEST_HEADERS, RequestHeadProgress,
    classify_framing, request_head_progress, te_is_chunked,
};
use hj_core::Proto;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub(crate) struct ConnectionPermit {
    active: Arc<std::sync::atomic::AtomicU64>,
}

impl ConnectionPermit {
    pub(crate) fn try_acquire(active: Arc<std::sync::atomic::AtomicU64>, cap: u32) -> Option<Self> {
        use std::sync::atomic::Ordering;

        let mut current = active.load(Ordering::Relaxed);
        loop {
            if cap != 0 && current >= u64::from(cap) {
                return None;
            }
            let next = current.checked_add(1)?;
            match active.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Some(Self { active }),
                Err(next) => current = next,
            }
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// What each monoio connection handler needs to serve a request: the on-core
/// cache-hit fast path (`pipeline::fast_serve`, no runtime hop) plus the bridge to
/// the tokio side-runtime for everything the fast path declines (miss / dynamic).
/// `holder` gives the live `ServerState` generation (SIGHUP-safe); `listener_name`
/// is the routing key for vhost resolution.
#[derive(Clone)]
pub(crate) struct CoreHandler {
    bridge: Bridge,
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
    listener_name: Arc<str>,
}

impl CoreHandler {
    /// Try the on-core cache-hit fast path; `Some(resp)` if served without the bridge.
    async fn fast(&self, ctx: &BridgeCtx, req: &hj_core::Request) -> Option<hj_core::Response> {
        let st = self.holder.load_full();
        // Stamp Date here (insert-if-absent): the page cache strips the stored Date
        // expecting the serve boundary to re-add one, and the uring writers never do — the
        // tokio path stamps at server::stamp_date, this is its on-core fast-path twin.
        crate::pipeline::fast_serve(
            &st,
            &self.listener_name,
            ctx.peer.ip(),
            ctx.local,
            ctx.peer.port(),
            ctx.is_tls,
            ctx.proto,
            ctx.tls.clone(),
            req,
        )
        .await
        .map(hj_core::stamp_date)
    }
}

/// Grace window for draining in-flight io_uring connections after the shutdown
/// signal: each per-core accept loop stops accepting, then waits up to this long
/// for live connections to finish (H1 closes idle keep-alives, H2 GOAWAYs + drains)
/// before the process exits. Mirrors the tokio path's bounded graceful shutdown.
const URING_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(15);
const WORKER_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(super) type WorkerReadyTx = std::sync::mpsc::Sender<Result<(), String>>;

fn wait_for_worker_readiness_with_timeout(
    label: &str,
    workers: usize,
    ready: std::sync::mpsc::Receiver<Result<(), String>>,
    timeout: std::time::Duration,
) -> io::Result<()> {
    if workers == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label}: no listener workers configured"),
        ));
    }
    let deadline = std::time::Instant::now() + timeout;
    for acknowledged in 0..workers {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match ready.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(io::Error::other(format!(
                    "{label}: worker startup failed: {error}"
                )));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{label}: only {acknowledged}/{workers} listener workers acknowledged readiness"
                    ),
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(format!(
                    "{label}: listener worker exited before readiness ({acknowledged}/{workers})"
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn wait_for_worker_readiness(
    label: &str,
    workers: usize,
    ready: std::sync::mpsc::Receiver<Result<(), String>>,
) -> io::Result<()> {
    wait_for_worker_readiness_with_timeout(label, workers, ready, WORKER_READY_TIMEOUT)
}

/// Per-core accept loop with graceful drain. Accepts until the shutdown signal,
/// then stops accepting and waits (bounded by [`URING_DRAIN_GRACE`]) for in-flight
/// connection tasks to complete. `on_accept` builds the (owned, `'static`) handler
/// future for each connection; an in-flight counter (single-thread `Rc<Cell>`, +1
/// at spawn, −1 when the handler future resolves) drives the drain wait.
async fn accept_drain_loop<F, Fut>(
    core_idx: usize,
    listener: TcpListener,
    shutdown: CancellationToken,
    secure: bool,
    core: CoreHandler,
    mut on_accept: F,
) where
    F: FnMut(TcpStream, SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()> + 'static,
{
    // Local per-core in-flight count keeps THIS core's runtime alive until its own
    // connections finish (so block_on doesn't return and drop the runtime mid-response).
    // The connections ALSO bump the shared `active_conns` gauge that main()'s shutdown
    // loop waits on before draining lsphp — so the io_uring path gets the SAME
    // drain-then-teardown ordering as the tokio path (no lsphp pulled out from under an
    // in-flight request).
    let inflight = std::rc::Rc::new(std::cell::Cell::new(0usize));
    // (#349) One access-chunk flush ticker per WORKER THREAD (several accept
    // loops share a thread): ships this thread's partially-filled access-log
    // chunks at latency bound even when traffic stops mid-chunk.
    thread_local! {
        static CHUNK_TICKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if !CHUNK_TICKER.with(|t| t.replace(true)) {
        let ticker_shutdown = shutdown.clone();
        monoio::spawn(async move {
            loop {
                monoio::select! {
                    _ = ticker_shutdown.cancelled() => break,
                    _ = monoio::time::sleep(std::time::Duration::from_millis(250)) => {
                        crate::pipeline::flush_access_chunks();
                    }
                }
            }
            crate::pipeline::flush_access_chunks();
        });
    }
    // (#334) One armed multishot SQE yields every inbound connection (no accept
    // submission per conn; peer addr via getpeername since multishot CQEs carry
    // no sockaddr). A terminal CQE re-arms once; if arming fails the loop falls
    // back to single-shot accept permanently. `--no-multishot-accept` disables.
    let mut multi = if MULTISHOT_ACCEPT.load(std::sync::atomic::Ordering::Relaxed) {
        listener.accept_multi().ok()
    } else {
        None
    };
    loop {
        crate::memtrim::collect_if_requested_on_thread();
        let next = async {
            loop {
                match multi.as_mut() {
                    Some(stream) => match stream.next().await {
                        Some(Ok(conn)) => match conn.peer_addr() {
                            Ok(peer) => return Ok((conn, peer)),
                            Err(e) => {
                                tracing::debug!(core = core_idx, secure, error = %e, "uring multishot accept: getpeername failed; dropping conn");
                                continue;
                            }
                        },
                        Some(Err(e)) => return Err(e),
                        None => {
                            multi = listener.accept_multi().ok();
                            if multi.is_none() {
                                tracing::warn!(
                                    core = core_idx,
                                    secure,
                                    "uring multishot accept: re-arm failed; falling back to single-shot"
                                );
                            }
                            continue;
                        }
                    },
                    None => return listener.accept().await,
                }
            }
        };
        monoio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            accepted = next => {
                match accepted {
                    Ok((stream, peer)) => {
                        let state = core.holder.load();
                        let cap = state.server.tuning.max_connections;
                        let active_conns = state.metrics.active_conns.clone();
                        let Some(permit) = ConnectionPermit::try_acquire(active_conns, cap) else {
                            tracing::debug!(core = core_idx, secure, limit = cap, "uring connection cap reached; rejecting");
                            continue;
                        };
                        // Disable Nagle, mirroring the tokio accept path (server.rs). monoio
                        // leaves TCP_NODELAY OFF by default, which stalls h1 request/response on
                        // mid-size bodies behind the peer's ~40 ms delayed ACK. The option is
                        // TCP-level and persists across the kTLS TCP_ULP upgrade on this fd.
                        let _ = stream.set_nodelay(true);
                        let fut = on_accept(stream, peer);
                        let cnt = inflight.clone();
                        cnt.set(cnt.get() + 1);
                        monoio::spawn(async move {
                            let _permit = permit;
                            fut.await;
                            cnt.set(cnt.get().saturating_sub(1));
                            crate::memtrim::collect_after_connection_close();
                        });
                    }
                    Err(e) => tracing::debug!(core = core_idx, secure, error = %e, "uring accept failed"),
                }
            }
        }
    }
    tracing::info!(
        core = core_idx,
        secure,
        in_flight = inflight.get(),
        "uring core: shutdown signalled — draining in-flight connections"
    );
    let start = std::time::Instant::now();
    while inflight.get() > 0 && start.elapsed() < URING_DRAIN_GRACE {
        monoio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if inflight.get() > 0 {
        tracing::warn!(
            core = core_idx,
            secure,
            remaining = inflight.get(),
            "uring core: drain grace elapsed; abandoning in-flight connections"
        );
    } else {
        tracing::info!(core = core_idx, secure, "uring core: drained cleanly");
    }
}

/// Dev smoke hook for H1 over the real pipeline with a minimal ServerState.
/// The production path is `serve` in `main.rs`, which builds the full
/// state once and calls `spawn_uring_http` / `spawn_uring_https`.
pub(crate) fn serve_uring(
    root: &std::path::Path,
    http_addr: SocketAddr,
    workers: usize,
) -> anyhow::Result<()> {
    let _ = hj_tls::install_crypto_provider();
    // Build ServerState + the bridge INSIDE a tokio runtime (ServerState/hj-log spawn
    // tasks that require an ambient runtime). The monoio io_uring cores run on their
    // own threads and bridge requests back to this runtime. This env-hook variant
    // builds a MINIMAL state (no lsphp/cache) for quick transport smoke; the
    // production path is `serve`, which shares serve()'s FULL state.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers.max(2))
        .thread_stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
        .on_thread_park(crate::memtrim::collect_if_requested_on_thread)
        .on_thread_stop(crate::memtrim::force_collect)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let cfg = hj_config::load(root)?;
        let server = Arc::new(cfg);
        let listener_name: Arc<str> = server
            .listeners
            .iter()
            .find(|l| !l.secure)
            .or_else(|| server.listeners.first())
            .map(|l| l.name.clone())
            .unwrap_or_else(|| "Default".to_string())
            .into();
        let state = ServerState::new(
            server,
            None,
            None,
            None,
            Arc::new(hj_compress::PageDictRegistry::empty()),
            2,
            crate::state::XfCapsuleConfig::disabled(),
            None,
            false,
            None,
            false,
            crate::state::RewriteTuning::default(),
        );
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let admission = pipeline_admission(holder.clone());
        spawn_uring_http(holder, listener_name, http_addr, workers, None, admission)?;
        // Keep this runtime alive to drive the bridge; the monoio cores run independently.
        std::future::pending::<()>().await;
        Ok::<(), anyhow::Error>(())
    })
}

/// Spawn the io_uring plaintext-HTTP transport: a cross-runtime bridge on the
/// CURRENT tokio runtime (each request loads the live `ServerState` generation
/// from `holder`, so SIGHUP reloads are honored) + one pinned-core monoio
/// io_uring runtime per worker, each adopting its own `SO_REUSEPORT` socket. The
/// monoio cores run on detached threads (process exit tears them down); the
/// returned `Ok(())` means the cores are up. Shared by `serve` (full
/// state) and the `serve_uring` smoke hook (minimal state).
pub(crate) fn spawn_uring_http(
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
    listener_name: Arc<str>,
    http_addr: SocketAddr,
    workers: usize,
    inherited: Option<Vec<std::net::TcpListener>>,
    admission: bridge::BridgeAdmission,
) -> anyhow::Result<()> {
    let shutdown = holder.load().shutdown.clone();
    let active_conns = holder.load().metrics.active_conns.clone();
    let bridge = build_pipeline_bridge(holder.clone(), listener_name.clone(), admission);
    let core = CoreHandler {
        bridge,
        holder,
        listener_name,
    };
    // Adopt the systemd socket-activation fds (one SO_REUSEPORT socket per worker,
    // bound as root by the .socket unit) when present — the process runs as `nobody`
    // and CANNOT self-bind privileged :80/:443. One monoio core per inherited fd;
    // self-bind workers-many only when there is no activation (alt-port/manual runs).
    let listeners = uring_listeners(inherited, http_addr, workers)?;
    let worker_count = listeners.len();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    for (core_i, std_listener) in listeners.into_iter().enumerate() {
        let core = core.clone();
        let shutdown = shutdown.clone();
        let active_conns = active_conns.clone();
        let ready = ready_tx.clone();
        std::thread::Builder::new()
            .name(format!("hj-uring-{core_i}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || {
                maybe_pin_core_thread(core_i, worker_count);
                per_core_bridged(
                    core_i,
                    std_listener,
                    http_addr,
                    core,
                    shutdown,
                    active_conns,
                    ready,
                )
            })?;
    }
    drop(ready_tx);
    wait_for_worker_readiness("HTTP", worker_count, ready_rx)?;
    Ok(())
}

/// (#296) Kill switch for per-core thread pinning (`--no-core-pinning`).
pub(crate) static CORE_PINNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// (#334) Kill switch for multishot accept (`--no-multishot-accept`): the
/// accept loops then submit one single-shot accept SQE per connection.
pub(crate) static MULTISHOT_ACCEPT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// (#330) Ring-setup mode for every monoio runtime this transport builds
/// (`--uring-ring legacy|coop|defer`).
pub(crate) const RING_LEGACY: u8 = 0;
pub(crate) const RING_COOP: u8 = 1;
pub(crate) const RING_DEFER: u8 = 2;
pub(crate) static RING_MODE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(RING_LEGACY);

/// (#330) Experiment-only ring-size override (`HJ_URING_ENTRIES`). Ring memory
/// is charged against RLIMIT_MEMLOCK for an unprivileged user — prod runs as
/// nobody under the unit's 8 MiB LimitMEMLOCK, where ~20 4096-entry rings
/// (~400 KiB each) BANKRUPT the budget and a late runtime fails to build at
/// all. That was the 2026-08-27 deploy crash-loop: the bridge runtime died at
/// startup, cache hits kept serving (on-core fast path) while every bridged
/// request 502'd, and readiness then took the process down. So the DEFAULT
/// stays monoio's 1024 entries (identical footprint to the proven binary);
/// bigger rings are an explicit alt-instance experiment.
fn uring_entries_override() -> Option<u32> {
    static ENTRIES: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *ENTRIES.get_or_init(|| {
        std::env::var("HJ_URING_ENTRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n >= 32)
    })
}

/// (#330) Build a per-core monoio io_uring runtime with the configured ring
/// setup. `coop` (default) = COOP_TASKRUN (completion task work runs on the
/// thread's own kernel transitions instead of via IPI — monoio re-enters the
/// kernel every park, so the work is never starved) + SUBMIT_ALL (an early
/// failed SQE no longer stops the batch), at monoio's default ring size.
/// `defer` additionally sets SINGLE_ISSUER + DEFER_TASKRUN (experiment-only:
/// completions then run ONLY inside this thread's enter; monoio's cross-thread
/// waker is eventfd-based so no foreign thread touches the ring, but this
/// stays opt-in until soaked). A kernel or rlimit that rejects the flagged
/// build falls back to a plain default ring (warned once) so ring tuning can
/// never cost availability.
pub(crate) fn build_core_runtime()
-> std::io::Result<monoio::Runtime<monoio::time::TimeDriver<monoio::IoUringDriver>>> {
    let mode = RING_MODE.load(std::sync::atomic::Ordering::Relaxed);
    let entries = uring_entries_override();
    if mode != RING_LEGACY {
        let mut urb = io_uring::IoUring::builder();
        urb.setup_coop_taskrun().setup_submit_all();
        if mode == RING_DEFER {
            urb.setup_single_issuer().setup_defer_taskrun();
        }
        let mut builder = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new().uring_builder(urb);
        if let Some(n) = entries {
            builder = builder.with_entries(n);
        }
        match builder.enable_timer().build() {
            Ok(rt) => return Ok(rt),
            Err(error) => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(%error, mode, ?entries, "uring: flagged ring build rejected; using plain default rings");
                });
            }
        }
    }
    monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
}

/// (#296) Pin the CALLING per-core transport thread to `core` — only when the
/// worker count equals the machine's CPU count, so each runtime owns exactly
/// one core (any other shape and the kernel's own placement beats a partial
/// pin). Gives the per-core io_uring state + SO_REUSEPORT socket L1/L2
/// locality and stops migration stalls. HISTORY: the per-core single-thread
/// RUNTIME change was reverted for uneven keepalive distribution — pinning
/// keeps today's runtime model but makes any placement unevenness permanent,
/// hence the self-gating condition, the `--no-core-pinning` kill switch, and
/// the pre-registered p99 watch in the campaign notes.
pub(crate) fn maybe_pin_core_thread(core: usize, workers: usize) {
    if !CORE_PINNING.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    if workers != cpus || core >= cpus {
        return;
    }
    // SAFETY: a zeroed cpu_set_t is a valid empty mask; CPU_SET stays in
    // bounds (core < cpus <= CPU_SETSIZE on any host this runs on); pid 0
    // targets the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            tracing::warn!(core, "uring: sched_setaffinity failed; running unpinned");
        }
    }
}

/// The per-core listener set for an io_uring transport: the inherited
/// socket-activation fds when present (kernel SO_REUSEPORT fan-out, already bound),
/// else `workers` freshly self-bound SO_REUSEPORT sockets.
fn uring_listeners(
    inherited: Option<Vec<std::net::TcpListener>>,
    addr: SocketAddr,
    workers: usize,
) -> io::Result<Vec<std::net::TcpListener>> {
    match inherited {
        Some(v) if !v.is_empty() => Ok(v),
        _ => (0..workers.max(1))
            .map(|_| reuseport_std_listener(addr))
            .collect(),
    }
}

/// Build the cross-runtime pipeline bridge on the CURRENT tokio runtime: each
/// request loads the live `ServerState` generation from `holder` (SIGHUP-safe) and
/// runs `pipeline::handle` with the per-connection context (peer/TLS/mTLS/SNI).
/// Shared by the plaintext (`spawn_uring_http`) and TLS (`spawn_uring_https`) paths.
fn build_pipeline_bridge(
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
    listener_name: Arc<str>,
    admission: bridge::BridgeAdmission,
) -> Bridge {
    // Capture THIS (current) tokio runtime so the cache's background maintenance tasks
    // (variant-fill / SWR refresh) — which the on-core fast path triggers from a monoio
    // thread with no tokio reactor — spawn onto it instead of panicking.
    crate::lscache::set_pipeline_runtime(tokio::runtime::Handle::current());
    // Same hazard class for hj-h2's file-body streaming: its chunks are pulled on the
    // monoio connection threads, so plant the tokio runtime its blocking reads run on.
    hj_h2::server::set_io_handle(tokio::runtime::Handle::current());
    // The pipeline only reads the name; share the Arc instead of re-allocating a String
    // for every bridged request (the closure runs concurrently across tokio workers).
    let lname = listener_name;
    bridge::spawn_on_current_with_admission(admission, move |req, ctx: BridgeCtx| {
        let state = holder.load_full();
        let lname = lname.clone();
        async move {
            // Stamp Date (insert-if-absent) on EVERY bridged response (H1/H2/H3): the uring
            // writers + native h2/h3 encoders don't add it and the cache strips the stored
            // one. Mirrors the tokio service boundary (server::stamp_date) so the two
            // transports never disagree on whether Date is present (RFC 9110 §6.6.1).
            let resp = crate::pipeline::handle(
                state,
                &lname,
                ctx.peer.ip(),
                ctx.local,
                ctx.peer.port(),
                ctx.is_tls,
                ctx.mtls_required,
                ctx.tls,
                ctx.proto,
                ctx.sni.as_deref(),
                req,
            )
            .await;
            hj_core::stamp_date(resp)
        }
    })
}

pub(crate) fn pipeline_admission(
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
) -> bridge::BridgeAdmission {
    bridge::BridgeAdmission::dynamic(move || {
        bridge::capacity_for_connection_limit(holder.load().server.tuning.max_connections)
    })
}

/// Spawn the io_uring HTTP/3 transport on `https_addr` (UDP): per-core monoio runtimes
/// driving quinn-proto, each dispatching requests through the SAME pipeline bridge as the
/// H1/H2 paths. This is the sole production H3 transport.
/// Must be called from within the ambient tokio runtime (the bridge receiver runs there).
pub(crate) fn spawn_uring_h3(
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
    listener_name: Arc<str>,
    https_addr: SocketAddr,
    workers: usize,
    rustls_cfg: Arc<rustls::ServerConfig>,
    require_client_cert: bool,
    inherited: Option<Vec<std::net::UdpSocket>>,
    admission: bridge::BridgeAdmission,
) -> anyhow::Result<()> {
    let shutdown = holder.load().shutdown.clone();
    let runtime = {
        let st = holder.load();
        let active_conns = st.metrics.active_conns.clone();
        drop(st);
        let config_holder = holder.clone();
        h3::H3RuntimeConfig::new(
            move || {
                let state = config_holder.load();
                (
                    h3::H3RequestLimits::new(
                        state.serve_config.max_req_header_size,
                        state.serve_config.max_req_body_size,
                    ),
                    state.server.tuning.max_connections,
                )
            },
            active_conns,
            // (#236 residual) process-lifetime budget shared with H1/H2/LSAPI.
            {
                let b = holder.load();
                b.body_budget.clone()
            },
        )
    };
    let bridge = build_pipeline_bridge(holder, listener_name, admission);
    h3::serve_h3_pipeline(
        https_addr,
        workers,
        rustls_cfg,
        bridge,
        require_client_cert,
        runtime,
        inherited,
        shutdown,
    )?;
    Ok(())
}

/// Spawn the io_uring TLS-HTTP transport on `https_addr`: one pinned-core monoio
/// runtime per worker, each adopting its own `SO_REUSEPORT` socket and terminating
/// TLS (rustls over monoio via monoio-rustls). After the handshake, ALPN selects
/// H1 vs H2 and the connection is served over the encrypted stream through the same
/// pipeline bridge. mTLS (clientVerify=2) is enforced at the application layer
/// exactly as the tokio path: a non-internal peer presenting no client cert is
/// refused post-handshake.
pub(crate) fn spawn_uring_https(
    holder: Arc<arc_swap::ArcSwap<ServerState>>,
    listener_name: Arc<str>,
    https_addr: SocketAddr,
    workers: usize,
    tls_config: Arc<rustls::ServerConfig>,
    require_client_cert: bool,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    inherited: Option<Vec<std::net::TcpListener>>,
    admission: bridge::BridgeAdmission,
) -> anyhow::Result<()> {
    let shutdown = holder.load().shutdown.clone();
    let active_conns = holder.load().metrics.active_conns.clone();
    let bridge = build_pipeline_bridge(holder.clone(), listener_name.clone(), admission);
    let core = CoreHandler {
        bridge,
        holder,
        listener_name,
    };
    let listeners = uring_listeners(inherited, https_addr, workers)?;
    let worker_count = listeners.len();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    for (core_i, std_listener) in listeners.into_iter().enumerate() {
        let core = core.clone();
        let shutdown = shutdown.clone();
        let active_conns = active_conns.clone();
        let acceptor: monoio_rustls::TlsAcceptor = tls_config.clone().into();
        let ktls_template = ktls_template.clone();
        let ready = ready_tx.clone();
        std::thread::Builder::new()
            .name(format!("hj-uring-tls-{core_i}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || {
                maybe_pin_core_thread(core_i, worker_count);
                per_core_https(
                    core_i,
                    std_listener,
                    https_addr,
                    core,
                    acceptor,
                    require_client_cert,
                    ktls_template,
                    shutdown,
                    active_conns,
                    ready,
                )
            })?;
    }
    drop(ready_tx);
    wait_for_worker_readiness("HTTPS", worker_count, ready_rx)?;
    Ok(())
}

fn per_core_https(
    core_idx: usize,
    std_listener: std::net::TcpListener,
    local: SocketAddr,
    core: CoreHandler,
    acceptor: monoio_rustls::TlsAcceptor,
    require_client_cert: bool,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    shutdown: CancellationToken,
    _active_conns: Arc<std::sync::atomic::AtomicU64>,
    ready: WorkerReadyTx,
) {
    let mut rt = match build_core_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(format!("build monoio runtime: {error}")));
            return;
        }
    };
    rt.block_on(async move {
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                let _ = ready.send(Err(format!("adopt listener: {e}")));
                tracing::error!(core = core_idx, error = %e, "uring tls: adopt reuseport listener failed");
                return;
            }
        };
        let _ = ready.send(Ok(()));
        tracing::info!(core = core_idx, "uring tls: per-core runtime serving (H1/H2 over TLS → real pipeline)");
        accept_drain_loop(core_idx, listener, shutdown.clone(), true, core.clone(), move |stream, peer| {
            handle_tls_bridged(stream, peer, local, core.clone(), acceptor.clone(), require_client_cert, ktls_template.clone(), shutdown.clone())
        })
        .await;
    });
}

/// Terminate TLS on a monoio io_uring connection, enforce mTLS, then serve H1/H2
/// (by ALPN) over the encrypted stream via the bridge. The connection metadata
/// (SNI, ALPN proto, SSL_* params, client-cert presence) is extracted by detaching
/// the rustls `ServerConnection` (only public accessor), draining any pipelined
/// post-handshake plaintext into the handler prefix (lossless), then reconstructing
/// the stream to serve.
async fn handle_tls_bridged(
    stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    core: CoreHandler,
    acceptor: monoio_rustls::TlsAcceptor,
    require_client_cert: bool,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    shutdown: CancellationToken,
) {
    // For the kTLS path we need this connection's OWN config carrying a per-connection
    // KeyLog (the only way to recover the raw traffic secrets for a later KeyUpdate rekey).
    // Build it per connection; non-kTLS reuses the shared acceptor.
    #[cfg(feature = "ktls")]
    let (acceptor, conn_key_log) = match &ktls_template {
        Some(t) => {
            let kl = Arc::new(ktls::ConnKeyLog::default());
            match t.server_config_with_key_log(kl.clone()) {
                Ok(cfg) => (monoio_rustls::TlsAcceptor::from(cfg), Some(kl)),
                Err(e) => {
                    tracing::warn!(error = %e, %peer, "uring ktls: per-connection config build failed; closing");
                    return;
                }
            }
        }
        None => (acceptor, None),
    };
    #[cfg(not(feature = "ktls"))]
    let _ = &ktls_template;

    let state = core.holder.load();
    let handshake_timeout = state.serve_config.header_read_timeout;
    let tls = match handshake_timeout {
        Some(d) => match monoio::time::timeout(d, acceptor.accept(stream)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, %peer, "uring tls: handshake rejected");
                return;
            }
            Err(_) => {
                tracing::debug!(%peer, "uring tls: handshake timed out");
                return;
            }
        },
        None => match acceptor.accept(stream).await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(error = %e, %peer, "uring tls: handshake rejected");
                return;
            }
        },
    };
    // Detach the session to read the handshake metadata (the `session` field is not
    // otherwise accessible), drain any early app-data, then rebuild the stream.
    let (io, mut session) = tls.into_parts();
    let sni: Option<Arc<str>> = session.server_name().map(Arc::from);
    let proto = match session.alpn_protocol() {
        Some(b"h2") => Proto::Http2,
        _ => Proto::Http1,
    };
    let has_client_cert = session.peer_certificates().is_some_and(|c| !c.is_empty());
    let tls_params = hj_tls::tls_params_from_conn(&session);
    // Application-layer mTLS (clientVerify=2): refuse a non-internal peer that
    // presented no valid client cert — mirrors server.rs::mtls_refused exactly.
    if require_client_cert && !has_client_cert && !hj_core::is_trusted_internal_peer(peer.ip()) {
        tracing::debug!(%peer, "uring tls: mTLS required, no client cert from non-internal peer; refusing");
        return;
    }
    // Drain any plaintext the client pipelined with the final handshake flight so it
    // is not lost when the stream is reconstructed (the prefix is handed to the
    // H1/H2 serve loop). Reads the already-decrypted buffer; no socket I/O.
    let mut prefix: Vec<u8> = Vec::new();
    {
        use std::io::Read;
        let mut reader = session.reader();
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => prefix.extend_from_slice(&buf[..n]),
                Err(_) => break, // WouldBlock = no buffered plaintext
            }
        }
    }
    let ctx = BridgeCtx {
        peer,
        local,
        proto,
        is_tls: true,
        mtls_required: require_client_cert,
        sni,
        tls: tls_params,
    };

    // kTLS path: upgrade the socket to kernel-TLS and serve plaintext over the RAW fd
    // (kernel encrypts/decrypts). `prefix` carries the post-handshake plaintext we drained,
    // so the kernel RX resumes at the correct record sequence. TLS 1.3 only (different key
    // schedule + no KeyUpdate on 1.2 ⇒ a 1.2 connection just falls through to userspace).
    #[cfg(feature = "ktls")]
    if let Some(kl) = conn_key_log {
        let is_tls13 = session.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
        let suite = session.negotiated_cipher_suite();
        if is_tls13 {
            match (kl.secrets(), suite) {
                (Some((rx, tx)), Some(suite)) => {
                    use std::os::fd::AsRawFd;
                    let fd = io.as_raw_fd();
                    // Read the true post-handshake record sequence for each direction (tickets
                    // already emitted advance TX; drained pipelined app-data advances RX) so the
                    // kernel keys are programmed at the right sequence. Consumes `session` —
                    // only on the committed kTLS path (the userspace fallback never extracts).
                    let (rx_seq, tx_seq) = match session.dangerous_extract_secrets() {
                        Ok(s) => (s.rx.0, s.tx.0),
                        Err(e) => {
                            tracing::warn!(error = %e, %peer, "uring ktls: secret extraction failed; closing");
                            return;
                        }
                    };
                    match ktls::into_ktls_stream(io, suite, rx, rx_seq, tx, tx_seq) {
                        Ok(ks) => {
                            match proto {
                                Proto::Http2 => {
                                    serve_h2_bridged(ks, prefix, ctx, core, shutdown, Some(fd))
                                        .await
                                }
                                _ => handle_h1_bridged(ks, prefix, ctx, core, shutdown).await,
                            }
                            return;
                        }
                        // `io` was consumed by the upgrade attempt — cannot fall back to
                        // userspace, so close (a TLS client must never get plaintext).
                        Err(e) => {
                            tracing::warn!(error = %e, %peer, fd, "uring ktls: fd upgrade failed; closing connection");
                            return;
                        }
                    }
                }
                // 1.3 but the KeyLog didn't capture both secrets (should not happen): fall
                // through to the userspace path with the intact io+session.
                _ => {
                    tracing::debug!(%peer, "uring ktls: secrets unavailable; serving via userspace TLS")
                }
            }
        }
        // else: TLS 1.2 ⇒ userspace path below (io+session still intact).
    }

    // Wrap the socket so monoio-rustls writes the encrypted bytes via a direct write(2)
    // syscall (not an io_uring write) — matching tokio's write path on loopback bulk egress.
    // rustls/aws-lc-rs still does the AEAD; this only changes the socket write.
    let stream = monoio_rustls::ServerTlsStream::new(
        directio::DirectWriteSocket::new_for(
            io,
            proto != Proto::Http2 || directio::h2_ring_writes(),
        ),
        session,
    );
    match proto {
        Proto::Http2 => serve_h2_bridged(stream, prefix, ctx, core, shutdown, None).await,
        _ => handle_h1_bridged(stream, prefix, ctx, core, shutdown).await,
    }
}

fn per_core_bridged(
    core_idx: usize,
    std_listener: std::net::TcpListener,
    local: SocketAddr,
    core: CoreHandler,
    shutdown: CancellationToken,
    _active_conns: Arc<std::sync::atomic::AtomicU64>,
    ready: WorkerReadyTx,
) {
    let mut rt = match build_core_runtime() {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(format!("build monoio runtime: {error}")));
            return;
        }
    };
    rt.block_on(async move {
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                let _ = ready.send(Err(format!("adopt listener: {e}")));
                tracing::error!(core = core_idx, error = %e, "uring serve: adopt reuseport listener failed");
                return;
            }
        };
        let _ = ready.send(Ok(()));
        tracing::info!(core = core_idx, "uring serve: per-core runtime serving (H1/h2c → real pipeline)");
        accept_drain_loop(core_idx, listener, shutdown.clone(), false, core.clone(), move |stream, peer| {
            handle_conn_bridged(stream, peer, local, core.clone(), shutdown.clone())
        })
        .await;
    });
}

/// h2c prior-knowledge connection preface (RFC 7540 §3.4). No HTTP/1.1 request
/// line can collide with it, so a prefix match is a safe protocol discriminator.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Sniff H1 vs the h2c prior-knowledge preface on a plaintext connection, then
/// route both through the bridge to the real pipeline. monoio streams aren't
/// peekable, so the discriminator bytes are read into `acc` and handed onward
/// (H1 reuses them as the head start; H2 seeds them as the preface prefix).
async fn handle_conn_bridged(
    mut stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    core: CoreHandler,
    shutdown: CancellationToken,
) {
    let state = core.holder.load();
    let header_read_timeout = state.serve_config.header_read_timeout;
    let request_start = std::time::Instant::now();
    let mut acc: Vec<u8> = Vec::with_capacity(8192);
    let mut read_scratch: Vec<u8> = Vec::new();
    let is_h2 = loop {
        let n = acc.len().min(H2_PREFACE.len());
        if acc[..n] != H2_PREFACE[..n] {
            break false; // diverged from the preface → HTTP/1.x
        }
        if acc.len() >= H2_PREFACE.len() {
            break true; // full preface matched → h2c prior knowledge
        }
        let elapsed = request_start.elapsed();
        let remaining = header_read_timeout.map(|d| d.saturating_sub(elapsed));
        if let Some(r) = remaining {
            if r.is_zero() {
                tracing::debug!(%peer, "uring h1: preface read timed out");
                return;
            }
        }
        match read_timeout(&mut stream, remaining, &mut read_scratch).await {
            Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
            _ => return,
        }
    };
    if is_h2 {
        serve_h2_bridged(
            stream,
            acc,
            BridgeCtx::plain(peer, local, Proto::Http2),
            core,
            shutdown,
            None,
        )
        .await;
    } else {
        handle_h1_bridged(
            stream,
            acc,
            BridgeCtx::plain(peer, local, Proto::Http1),
            core,
            shutdown,
        )
        .await;
    }
}

/// Serve an H2 connection over `stream` (plaintext or TLS) via the bridge: a
/// per-stream service closure dispatches each request to the real pipeline with a
/// clone of the connection `ctx`. `prefix` seeds the h2 preface bytes already read.
async fn serve_h2_bridged<S>(
    stream: S,
    prefix: Vec<u8>,
    ctx: BridgeCtx,
    core: CoreHandler,
    shutdown: CancellationToken,
    ktls_fd: Option<i32>,
) where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Split + 'static,
{
    let state = core.holder.load();
    let mut h2_cfg = hj_h2::server::Config::default();
    h2_cfg.conn_idle_timeout = state
        .serve_config
        .keep_alive_timeout
        .map(|t| t.max(std::time::Duration::from_secs(90))); // keep-alive proxy padding
    h2_cfg.preface_timeout = state.serve_config.header_read_timeout;
    h2_cfg.header_list_size = state.serve_config.max_req_header_size as u32;
    h2_cfg.max_request_body = state.serve_config.max_req_body_size;
    // (#236 residual) share the server-wide buffered-body cap with H1/H3/LSAPI.
    h2_cfg.body_budget = Some(state.body_budget.clone());

    let service = move |req: hj_core::Request| {
        let core = core.clone();
        let ctx = ctx.clone();
        async move {
            // On-core cache-hit fast path (no bridge hop); else dispatch to the pipeline.
            if let Some(resp) = core.fast(&ctx, &req).await {
                return resp;
            }
            core.bridge.dispatch_response(req, ctx).await
        }
    };
    // `ktls_fd` (Some only for a kTLS connection) lets the h2 flush writev plaintext directly
    // from the OutQueue to the kernel-TLS socket (zero-copy); None ⇒ the coalesce path.
    if let Err(e) = hj_h2::server::serve_local_with_prefix(
        stream,
        prefix,
        service,
        h2_cfg,
        Some(shutdown),
        ktls_fd,
    )
    .await
    {
        tracing::debug!(error = %e, "uring serve: h2 connection ended");
    }
}

/// LiteSpeed `maxKeepAliveReq`: `max == 0` ⇒ unlimited; otherwise the keep-alive connection
/// closes once it has SERVED `max` requests. `served` is 1-based (incremented before the check),
/// so `max == N` serves exactly N requests then closes on the Nth response.
fn keepalive_exhausted(served: u32, max: u32) -> bool {
    max != 0 && served >= max
}

/// Real HTTP/1.1 over io_uring (plaintext or TLS stream) dispatched to the pipeline
/// via the bridge: parse the full request (method/uri/headers/body),
/// `bridge.dispatch`, then write the real response. Keep-alive loop; pipelining via
/// the retained buffer. `acc` is seeded with the bytes the protocol sniffer / TLS
/// handshake already surfaced. `ctx` carries the per-connection peer/TLS metadata.
async fn handle_h1_bridged<S>(
    mut stream: S,
    mut acc: Vec<u8>,
    ctx: BridgeCtx,
    core: CoreHandler,
    shutdown: CancellationToken,
) where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Split + 'static,
{
    // Requests served on this keep-alive connection (LiteSpeed maxKeepAliveReq enforcement).
    let mut served: u32 = 0;
    let mut read_scratch: Vec<u8> = Vec::new();
    loop {
        let state = core.holder.load();
        // Request-size caps from the LiteSpeed config (maxReqHeaderSize/maxReqBodySize),
        // matching the tokio path — mirror hyper's `max_buf_size` 8 KiB floor for the head.
        let max_head = state.serve_config.max_req_header_size.max(8192);
        let max_body = state.serve_config.max_req_body_size;
        // maxKeepAliveReq: 0 = unlimited; else close the connection after N requests.
        let max_keepalive = state.serve_config.max_keepalive_requests;
        // Graceful drain: at a clean request boundary (no buffered bytes = idle
        // keep-alive), wait for either the next request OR the shutdown signal — on
        // shutdown, close the idle connection promptly instead of holding it open.
        // Mid-request reads below are NOT interruptible, so an in-flight request always
        // finishes. (A read cancelled here is harmless: we close immediately, so the
        // non-cancel-safe TLS read buffer is never touched again.)
        if acc.is_empty() {
            // (audit M2) One huge upload used to pin its peak `acc` capacity on this
            // keep-alive connection forever; hand it back at the request boundary.
            if acc.capacity() > 256 * 1024 {
                acc = Vec::with_capacity(8192);
            }
            // (#303) Same proxy-padding floor the H2 idle window applies: CF's edge
            // keeps idle origin connections well past a 5s keepAliveTimeout, and an
            // unpadded H1 idle wait closes them almost immediately (constant
            // reconnect + TLS-handshake churn). H2 has padded to >=90s for a while.
            let keep_alive_timeout = state
                .serve_config
                .keep_alive_timeout
                .map(|t| t.max(std::time::Duration::from_secs(90)));
            monoio::select! {
                biased;
                res = read_timeout(&mut stream, keep_alive_timeout, &mut read_scratch) => {
                    match res {
                        Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
                        _ => return, // EOF, error, or keep-alive timeout
                    }
                }
                _ = shutdown.cancelled() => {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
        }
        // Parse a complete request head (drops the borrow before mutating `acc`).
        let request_start = std::time::Instant::now();
        let header_read_timeout = state.serve_config.header_read_timeout;
        let parsed = loop {
            let step: ParsedReq = {
                let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                match request_head_progress(req.parse(&acc), acc.len(), max_head) {
                    RequestHeadProgress::Complete(head_len) => materialize_head(&req, head_len),
                    RequestHeadProgress::Partial => ParsedReq::Partial,
                    RequestHeadProgress::TooLarge => ParsedReq::HeadersTooLarge,
                    RequestHeadProgress::Bad => ParsedReq::Bad,
                }
            };
            match step {
                ParsedReq::Done {
                    method,
                    uri,
                    headers,
                    head_len,
                    framing,
                    keep_alive,
                    expect_continue,
                } => {
                    break (
                        method,
                        uri,
                        headers,
                        head_len,
                        framing,
                        keep_alive,
                        expect_continue,
                    );
                }
                ParsedReq::Bad => {
                    // (#233) An unparsable head (bad method/target/header token) used to
                    // close the connection with zero response bytes: clients see "empty
                    // reply", Cloudflare retries against the peer, and nothing reaches the
                    // access log because the funnel is never entered. Answer 400 + close
                    // like every sibling refusal path (and hyper/LiteSpeed) instead.
                    write_status_close(&mut stream, 400, "Bad Request").await;
                    return;
                }
                ParsedReq::HeadersTooLarge => {
                    write_status_close(&mut stream, 431, "Request Header Fields Too Large").await;
                    return;
                }
                ParsedReq::Partial => {
                    if acc.len() > max_head {
                        write_status_close(&mut stream, 431, "Request Header Fields Too Large")
                            .await;
                        return;
                    }
                    let elapsed = request_start.elapsed();
                    let remaining = header_read_timeout.map(|d| d.saturating_sub(elapsed));
                    if let Some(r) = remaining {
                        if r.is_zero() {
                            tracing::debug!(%ctx.peer, "uring h1: header read timed out");
                            return;
                        }
                    }
                    match read_timeout(&mut stream, remaining, &mut read_scratch).await {
                        Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
                        _ => return,
                    }
                }
            }
        };
        let (method, uri, mut headers, head_len, framing, mut keep_alive, expect_continue) = parsed;
        // maxKeepAliveReq: once this connection has served the configured number of requests,
        // signal close on this (final) response so the client opens a fresh connection.
        served = served.saturating_add(1);
        if keepalive_exhausted(served, max_keepalive) {
            keep_alive = false;
        }
        // Server-wide buffered-body reservation (#236 residual): the transport commits
        // body bytes to heap BEFORE any handler runs, so the cap must be enforced here,
        // not only in hj-lsapi's collect_to_cap. The lease is held for the rest of this
        // keep-alive iteration (the buffered Bytes live exactly that long).
        let mut body_lease: Option<hj_core::budget::BodyBufferLease> = None;
        let body_bytes: bytes::Bytes = match framing {
            BodyFraming::Reject => {
                write_status_close(&mut stream, 400, "Bad Request").await;
                return;
            }
            BodyFraming::Length(content_length) => {
                // Bound buffered request-body memory: reject an oversized declared length
                // up front (413) instead of reading gigabytes into `acc`.
                if content_length > max_body {
                    write_status_close(&mut stream, 413, "Payload Too Large").await;
                    return;
                }
                // (security #263) Reserve INCREMENTALLY: only the first 64 KiB is
                // committed before any byte arrives. Reserving the whole declared
                // length up front let ~6 slow connections pin the entire server-wide
                // budget and 503 every POST/upload server-wide.
                const UPFRONT_RESERVE: u64 = 64 * 1024;
                let mut reserved: u64 = 0;
                let mut ensure_reserved =
                    |lease: &mut Option<hj_core::budget::BodyBufferLease>, buffered: u64| -> bool {
                        if buffered <= reserved {
                            return true;
                        }
                        let ok = lease
                            .get_or_insert_with(|| {
                                hj_core::budget::BodyBufferLease::new(state.body_budget.clone())
                            })
                            .reserve(buffered - reserved);
                        if ok {
                            reserved = buffered;
                        }
                        ok
                    };
                if content_length > 0 {
                    let upfront = (content_length as u64).min(UPFRONT_RESERVE);
                    if !ensure_reserved(&mut body_lease, upfront) {
                        // Server capacity, not client error — same status collect_to_cap uses.
                        tracing::debug!(%ctx.peer, "uring h1: body buffer budget exhausted");
                        write_status_close(&mut stream, 503, "Service Unavailable").await;
                        return;
                    }
                }
                let total = head_len.saturating_add(content_length);
                // Send the interim 100 only if we still need to wait for body bytes (a
                // client that already streamed the body doesn't need it).
                if expect_continue && content_length > 0 && acc.len() < total {
                    write_continue(&mut stream).await;
                }
                while acc.len() < total {
                    match read_timeout(&mut stream, header_read_timeout, &mut read_scratch).await {
                        Ok(n) if n > 0 => {
                            acc.extend_from_slice(&read_scratch[..n]);
                            // Top the reservation up to the bytes actually buffered.
                            let buffered =
                                (acc.len().saturating_sub(head_len)).min(content_length) as u64;
                            if !ensure_reserved(&mut body_lease, buffered) {
                                tracing::debug!(
                                    %ctx.peer,
                                    "uring h1: body buffer budget exhausted mid-body"
                                );
                                write_status_close(&mut stream, 503, "Service Unavailable").await;
                                return;
                            }
                        }
                        _ => return,
                    }
                }
                let bb = bytes::Bytes::copy_from_slice(&acc[head_len..total]);
                acc.drain(..total);
                bb
            }
            BodyFraming::Chunked => {
                // Decode the chunked body framing so the keep-alive buffer stays aligned
                // (a missed TE here = body loss + request smuggling). The decoder is a
                // resumable cursor over `acc`; we read more only when it asks.
                let mut dec = ChunkedDecoder::new(head_len);
                dec.max_body = max_body;
                dec.max_raw = max_body.saturating_add(1 << 20);
                // A chunked request always carries a body; honor Expect before draining it.
                if expect_continue {
                    write_continue(&mut stream).await;
                }
                // Reserve incrementally AS BYTES DECODE (never trust the client's framing
                // to pre-declare anything): the decoded length is the heap we commit.
                let mut decoded_prev = 0usize;
                let end = loop {
                    let step = dec.advance(&acc);
                    let grown = dec.body.len() - decoded_prev;
                    if grown > 0 {
                        let ok = body_lease
                            .get_or_insert_with(|| {
                                hj_core::budget::BodyBufferLease::new(state.body_budget.clone())
                            })
                            .reserve(grown as u64);
                        if !ok {
                            tracing::debug!(%ctx.peer, "uring h1: body buffer budget exhausted");
                            write_status_close(&mut stream, 503, "Service Unavailable").await;
                            return;
                        }
                        decoded_prev = dec.body.len();
                    }
                    match step {
                        ChunkStep::Done(end) => break end,
                        ChunkStep::Bad => {
                            write_status_close(&mut stream, 400, "Bad Request").await;
                            return;
                        }
                        ChunkStep::NeedMore => {
                            match read_timeout(&mut stream, header_read_timeout, &mut read_scratch)
                                .await
                            {
                                Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
                                _ => return,
                            }
                        }
                    }
                };
                let bb = bytes::Bytes::from(std::mem::take(&mut dec.body));
                acc.drain(..end);
                // Transfer-Encoding was stripped; hand the backend an explicit length so
                // CONTENT_LENGTH/$_SERVER and LSAPI framing are correct.
                // classify_framing already rejected TE+CL, so no CL exists to shadow.
                if let Ok(v) = http::HeaderValue::from_str(&bb.len().to_string()) {
                    headers.insert(http::header::CONTENT_LENGTH, v);
                }
                bb
            }
        };

        // Build the full hj_core::Request.
        let body: hj_core::IncomingBody = if body_bytes.is_empty() {
            hj_core::empty_incoming()
        } else {
            use http_body_util::BodyExt;
            http_body_util::Full::new(body_bytes)
                .map_err(|n| match n {})
                .boxed()
        };
        // (#277) Direct construction — the Method/Uri/HeaderMap were fully
        // validated + materialized ONCE at intake (an httparse-accepted-but-
        // Uri-rejected target answered 400+close there, preserving #233), so
        // the builder's per-header revalidation loop and its late error path
        // have nothing left to do.
        let mut req = http::Request::new(body);
        *req.method_mut() = method.clone();
        *req.uri_mut() = uri;
        *req.version_mut() = http::Version::HTTP_11;
        *req.headers_mut() = headers;
        let mut upgrade_ready = None;
        if hj_proxy::is_websocket_upgrade(req.headers()) {
            let (upgrade, ready) = bridge::UringUpgradeRequest::channel();
            req.extensions_mut().insert(upgrade);
            upgrade_ready = Some(ready);
        }
        // On-core cache-hit fast path first (no bridge hop); else dispatch across the bridge.
        let resp: bridge::BridgeResp = if upgrade_ready.is_none() {
            match core.fast(&ctx, &req).await {
                Some(r) => {
                    let (p, b) = r.into_parts();
                    // The fast path is buffered; a failed/short file read becomes a clean 502 before
                    // any success headers are committed.
                    let (body_bytes, truncated) = bridge::buffer_body(b).await;
                    if truncated {
                        bridge::bad_gateway()
                    } else {
                        bridge::BridgeResp {
                            status: p.status,
                            headers: p.headers,
                            body: bridge::BridgeBody::Full(body_bytes),
                        }
                    }
                }
                _ => match core.bridge.dispatch(req, ctx.clone()).await {
                    Some(br) => br,
                    None => return,
                },
            }
        } else {
            match core.bridge.dispatch(req, ctx.clone()).await {
                Some(br) => br,
                None => return,
            }
        };
        if resp.status == http::StatusCode::SWITCHING_PROTOCOLS {
            let Some(mut ready) = upgrade_ready else {
                write_status_close(&mut stream, 502, "Bad Gateway").await;
                return;
            };
            let Some(upgrade) = ready.recv().await else {
                write_status_close(&mut stream, 502, "Bad Gateway").await;
                return;
            };
            let head = serialize_h1_upgrade_response(resp.status, &resp.headers);
            let (written, _) = stream.write_all(head).await;
            if written.is_err() {
                return;
            }
            relay_h1_upgrade(stream, std::mem::take(&mut acc), upgrade).await;
            return;
        }
        let is_head = method == http::Method::HEAD;
        // Full → one vectored head/body write; Stream → head then drained chunks.
        let must_close = write_h1_response(&mut stream, resp, is_head, keep_alive).await;
        if must_close {
            let _ = stream.shutdown().await;
            return;
        }
    }
}

enum ParsedReq {
    Done {
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
        head_len: usize,
        framing: BodyFraming,
        keep_alive: bool,
        expect_continue: bool,
    },
    Partial,
    Bad,
    /// Configured byte cap or `MAX_REQUEST_HEADERS` field slots exceeded — answer 431.
    HeadersTooLarge,
}

/// (#277) Materialize a completed `httparse::Request` head ONCE into typed
/// `Method`/`Uri`/`HeaderMap` plus the framing/keep-alive/expect decisions.
/// The old intake built method/path Strings and a `Vec<(HeaderName,
/// HeaderValue)>`, then re-inserted every header through `Request::builder`
/// (which re-validated each name/value and re-parsed the URI); this builds the
/// pre-sized map and parses the URI a single time. An httparse-accepted-but-
/// `http::Uri`-rejected target returns `Bad` here (answered 400+close), exactly
/// as the builder's late URI error did (#233); dup-Host and TE/CL smuggling
/// shapes still resolve to `BodyFraming::Reject` via the unchanged
/// `classify_framing`. Pure over the parsed head so it can be tested directly.
fn materialize_head(req: &httparse::Request<'_, '_>, head_len: usize) -> ParsedReq {
    let method = match http::Method::from_bytes(req.method.unwrap_or("GET").as_bytes()) {
        Ok(m) => m,
        Err(_) => return ParsedReq::Bad,
    };
    let uri = match req.path.unwrap_or("/").parse::<http::Uri>() {
        Ok(u) => u,
        Err(_) => return ParsedReq::Bad,
    };
    let mut hdr_map = http::HeaderMap::with_capacity(req.headers.len());
    let mut cl_values: Vec<&[u8]> = Vec::new();
    let mut chunked = false;
    let mut te_other = false;
    let mut host_count = 0usize;
    let mut conn_close = req.version == Some(0);
    // RFC 7231 §5.1.1: honor `Expect: 100-continue` (HTTP/1.1 only) by
    // sending an interim 100 before reading the body, so a client that
    // withholds the body pending it isn't stalled to the header timeout.
    let mut expect_continue = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("expect") {
            expect_continue = req.version == Some(1) && expect_is_100_continue(h.value);
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            cl_values.push(h.value);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            // We frame the body ourselves; Transfer-Encoding is hop-by-hop and
            // is never forwarded downstream. Only a lone `chunked` is framable
            // here — any other coding (or a non-final/compound TE) we cannot
            // length-frame, so flag it for rejection rather than guess.
            if te_is_chunked(h.value) {
                chunked = true;
            } else {
                te_other = true;
            }
            continue;
        } else if h.name.eq_ignore_ascii_case("host") {
            host_count += 1;
        } else if h.name.eq_ignore_ascii_case("connection") {
            // RFC 7230 §6.1: Connection is a comma-separated token list
            // (e.g. `close, Upgrade`). Match each token, not the whole
            // value — a whole-value compare misses `close` in a multi-token
            // header and mis-frames keep-alive.
            for tok in h.value.split(|&b| b == b',') {
                let tok = tok.trim_ascii();
                if tok.eq_ignore_ascii_case(b"close") {
                    conn_close = true;
                } else if tok.eq_ignore_ascii_case(b"keep-alive") {
                    conn_close = false;
                }
            }
        }
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_bytes(h.value),
        ) {
            hdr_map.append(n, v);
        }
    }
    // RFC 7230 §3.3.3: reject smuggling-prone framing — both TE and CL present,
    // a non-chunked/compound TE, a non-numeric/overflowing CL, or conflicting
    // duplicate CL values. (A malformed/duplicate CL silently coerced to a length
    // would frame the body short and leak the trailing bytes as the next request.)
    // Decided by `codec::classify_framing` so the served path and the fuzzers agree.
    let framing = if host_count > 1 {
        // RFC 9112 §3.2: a request with multiple Host lines is malformed
        // (MUST reject or replace). Routing, foreign-host protection and
        // cache keys read only the first while hj-proxy forwards BOTH —
        // so reject rather than forward the ambiguity.
        BodyFraming::Reject
    } else {
        classify_framing(cl_values.iter().copied(), chunked, te_other)
    };
    ParsedReq::Done {
        method,
        uri,
        headers: hdr_map,
        head_len,
        framing,
        keep_alive: !conn_close,
        expect_continue,
    }
}

// The pure request-framing primitives (`BodyFraming`, `classify_framing`,
// `ChunkedDecoder`, `te_is_chunked`, `resolve_content_length`, `parse_chunk_size`)
// live in `codec.rs` — synchronous and fuzz-reachable via the crate `lib.rs`. Imported above.

/// Write a minimal status line + `Connection: close` and shut the connection down.
/// Used to refuse a smuggling-prone / unframable request without dispatching it.
async fn write_status_close<S>(stream: &mut S, status: u16, reason: &str)
where
    S: AsyncWriteRent,
{
    let head =
        format!("HTTP/1.1 {status} {reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    let _ = stream.write_all(head.into_bytes()).await;
    let _ = stream.shutdown().await;
}

/// An `Expect` header value requests `100-continue` (token, case-insensitive, OWS-trimmed).
fn expect_is_100_continue(value: &[u8]) -> bool {
    value.trim_ascii().eq_ignore_ascii_case(b"100-continue")
}

/// Write an interim `100 Continue` (RFC 7231 §5.1.1) without closing — the body read
/// and final response follow on the same connection.
async fn write_continue<S>(stream: &mut S)
where
    S: AsyncWriteRent,
{
    let _ = stream
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())
        .await;
}

/// Hop-by-hop response headers the io_uring H1 writer manages itself and must NOT
/// forward verbatim from a backend (RFC 7230 §6.1 + the framing headers we re-emit).
/// `HeaderName::as_str()` is always lowercase.
fn is_hop_by_hop_response(n: &http::HeaderName) -> bool {
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "proxy-connection"
            | "proxy-authenticate"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H1ResponseFraming {
    ContentLength(u64),
    Chunked,
    None,
}

fn declared_response_length(headers: &http::HeaderMap) -> Option<u64> {
    let mut declared = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH) {
        let parsed = value.to_str().ok()?.trim().parse::<u64>().ok()?;
        if declared.is_some_and(|prior| prior != parsed) {
            return None;
        }
        declared = Some(parsed);
    }
    declared
}

fn h1_response_framing(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    known_len: Option<u64>,
    is_head: bool,
) -> H1ResponseFraming {
    if status.is_informational() || status == http::StatusCode::NO_CONTENT {
        return H1ResponseFraming::None;
    }
    if status == http::StatusCode::RESET_CONTENT {
        return H1ResponseFraming::ContentLength(0);
    }
    if status == http::StatusCode::NOT_MODIFIED || is_head {
        return declared_response_length(headers)
            .or(known_len)
            .map_or(H1ResponseFraming::None, H1ResponseFraming::ContentLength);
    }
    known_len.map_or(H1ResponseFraming::Chunked, H1ResponseFraming::ContentLength)
}

/// Serialize an HTTP/1.1 response head. Buffered response bodies are written separately with
/// `writev`, so a large `Bytes` body is not copied into a head-plus-body allocation. Header
/// values are written as raw bytes (a non-visible-ASCII value is valid in an `HeaderValue` and
/// must not be silently dropped). Hop-by-hop + the backend's own content-length are stripped;
/// the transport emits status-appropriate framing itself.
/// Decimal digits appended in place — the per-response head serializer used to pay two
/// `format!` heap temporaries for exactly these numbers.
#[inline]
fn push_u64_decimal(out: &mut Vec<u8>, v: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    let mut v = v;
    loop {
        i -= 1;
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

/// Lowercase hex digits appended in place (chunked-transfer size prefixes).
#[inline]
fn push_u64_hex(out: &mut Vec<u8>, v: u64) {
    let mut tmp = [0u8; 16];
    let mut i = tmp.len();
    let mut v = v;
    loop {
        i -= 1;
        tmp[i] = b"0123456789abcdef"[(v & 0xF) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

/// Status line bytes ("HTTP/1.1 <code> <reason>\r\n") appended without format! temporaries.
#[inline]
fn push_h1_status_line(out: &mut Vec<u8>, status: http::StatusCode, reason: &str) {
    out.extend_from_slice(b"HTTP/1.1 ");
    push_u64_decimal(out, status.as_u16() as u64);
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn serialize_h1_response_head(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body_len: usize,
    is_head: bool,
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut out: Vec<u8> = Vec::with_capacity(256);
    push_h1_status_line(&mut out, status, reason);
    for (n, v) in headers.iter() {
        if n == http::header::CONTENT_LENGTH || is_hop_by_hop_response(n) {
            continue;
        }
        out.extend_from_slice(n.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match h1_response_framing(status, headers, Some(body_len as u64), is_head) {
        H1ResponseFraming::ContentLength(n) => {
            out.extend_from_slice(b"content-length: ");
            push_u64_decimal(&mut out, n);
            out.extend_from_slice(b"\r\n");
        }
        H1ResponseFraming::Chunked => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        H1ResponseFraming::None => {}
    }
    out.extend_from_slice(if keep_alive {
        b"connection: keep-alive\r\n\r\n"
    } else {
        b"connection: close\r\n\r\n"
    });
    out
}

async fn write_h1_vectored<S>(stream: &mut S, parts: Vec<bytes::Bytes>) -> io::Result<()>
where
    S: AsyncWriteRent,
{
    let buffer = hj_h2::owned_iovec::OwnedIoVec::from_bytes(parts)?;
    hj_h2::owned_iovec::write_all_owned(stream, buffer).await?;
    Ok(())
}

fn serialize_h1_upgrade_response(status: http::StatusCode, headers: &http::HeaderMap) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut out = Vec::with_capacity(256);
    push_h1_status_line(&mut out, status, reason);
    let mut has_connection = false;
    let mut has_upgrade = false;
    for (name, value) in headers {
        if name == http::header::CONTENT_LENGTH
            || name == http::header::TRANSFER_ENCODING
            || name.as_str() == "keep-alive"
            || name.as_str() == "proxy-connection"
        {
            continue;
        }
        has_connection |= name == http::header::CONNECTION;
        has_upgrade |= name == http::header::UPGRADE;
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_upgrade {
        out.extend_from_slice(b"upgrade: websocket\r\n");
    }
    if !has_connection {
        out.extend_from_slice(b"connection: upgrade\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

async fn relay_h1_upgrade<S>(stream: S, prefix: Vec<u8>, upgrade: bridge::UringUpgradeIo)
where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Split + 'static,
{
    use monoio::io::Splitable;

    let (mut reader, mut writer) = stream.into_split();
    let bridge::UringUpgradeIo {
        to_upstream,
        mut from_upstream,
    } = upgrade;
    let to_upstream = async move {
        if !prefix.is_empty() && to_upstream.send(bytes::Bytes::from(prefix)).await.is_err() {
            return;
        }
        loop {
            let (result, buffer) = reader.read(vec![0u8; 16 * 1024]).await;
            let Ok(read) = result else { return };
            if read == 0 {
                return;
            }
            if to_upstream
                .send(bytes::Bytes::copy_from_slice(&buffer[..read]))
                .await
                .is_err()
            {
                return;
            }
        }
    };
    let from_upstream = async move {
        while let Some(item) = from_upstream.recv().await {
            let Ok(bytes) = item else { return };
            let (result, _) = writer.write_all(bytes.to_vec()).await;
            if result.is_err() {
                return;
            }
        }
        let _ = writer.shutdown().await;
    };
    monoio::select! {
        _ = to_upstream => {}
        _ = from_upstream => {}
    }
}

/// Write a `BridgeResp` to the H1 wire. `Full` gathers the head and body in one vectored write;
/// `Stream` writes the head then drains chunks. Returns true if the connection must close
/// (write error, no keep-alive, or a mid-stream abort that desynced framing).
async fn write_h1_response<S>(
    stream: &mut S,
    resp: bridge::BridgeResp,
    is_head: bool,
    keep_alive: bool,
) -> bool
where
    S: AsyncWriteRent,
{
    match resp.body {
        bridge::BridgeBody::Full(body) => {
            let head = serialize_h1_response_head(
                resp.status,
                &resp.headers,
                body.len(),
                is_head,
                keep_alive,
            );
            let body_forbidden = hj_core::response_body_forbidden(is_head, resp.status);
            let result = if body_forbidden || body.is_empty() {
                stream.write_all(head).await.0.map(|_| ())
            } else {
                write_h1_vectored(stream, vec![bytes::Bytes::from(head), body]).await
            };
            result.is_err() || !keep_alive
        }
        bridge::BridgeBody::Stream { rx, len } => {
            write_h1_stream(
                stream,
                resp.status,
                &resp.headers,
                rx,
                len,
                is_head,
                keep_alive,
            )
            .await
        }
    }
}

/// Write a streamed H1 response: head, then drain the chunk channel. `len: Some(n)` ⇒
/// `content-length: n` + raw bytes (resumable downloads); `None` ⇒ `transfer-encoding:
/// chunked`. `HEAD` and body-forbidden statuses write only the head. An `Err(())` from the
/// channel is a mid-stream upstream abort AFTER the head was sent — we can no longer 502, so
/// close the connection (a partial body under CL, or an unterminated chunked stream, would
/// desync the next pipelined request).
async fn write_h1_stream<S>(
    stream: &mut S,
    status: http::StatusCode,
    headers: &http::HeaderMap,
    mut rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ()>>,
    len: Option<u64>,
    is_head: bool,
    keep_alive: bool,
) -> bool
where
    S: AsyncWriteRent,
{
    let head = serialize_h1_stream_head(status, headers, len, is_head, keep_alive);
    let (wres, _h) = stream.write_all(head).await;
    if wres.is_err() {
        return true;
    }
    if hj_core::response_body_forbidden(is_head, status) {
        rx.close();
        return !keep_alive;
    }
    let chunked = len.is_none();
    while let Some(item) = rx.recv().await {
        match item {
            Ok(b) => {
                if b.is_empty() {
                    continue;
                }
                let result = if chunked {
                    let mut prefix = Vec::with_capacity(20);
                    push_u64_hex(&mut prefix, b.len() as u64);
                    prefix.extend_from_slice(b"\r\n");
                    write_h1_vectored(
                        stream,
                        vec![
                            bytes::Bytes::from(prefix),
                            b,
                            bytes::Bytes::from_static(b"\r\n"),
                        ],
                    )
                    .await
                } else {
                    stream.write_all(b).await.0.map(|_| ())
                };
                if result.is_err() {
                    return true;
                }
            }
            Err(()) => return true, // mid-stream upstream abort → close (framing desynced)
        }
    }
    if chunked {
        let (w, _b) = stream
            .write_all(bytes::Bytes::from_static(b"0\r\n\r\n"))
            .await;
        if w.is_err() {
            return true;
        }
    }
    !keep_alive
}

/// Serialize the HEAD of a STREAMED H1 response. `len: Some(n)` ⇒ `content-length: n`;
/// `None` ⇒ `transfer-encoding: chunked`. Same hop-by-hop / backend-CL stripping as
/// [`serialize_h1_response_head`].
fn serialize_h1_stream_head(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    len: Option<u64>,
    is_head: bool,
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut out: Vec<u8> = Vec::with_capacity(256);
    push_h1_status_line(&mut out, status, reason);
    for (n, v) in headers.iter() {
        if n == http::header::CONTENT_LENGTH || is_hop_by_hop_response(n) {
            continue;
        }
        out.extend_from_slice(n.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match h1_response_framing(status, headers, len, is_head) {
        H1ResponseFraming::ContentLength(n) => {
            out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes())
        }
        H1ResponseFraming::Chunked => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        H1ResponseFraming::None => {}
    }
    out.extend_from_slice(if keep_alive {
        b"connection: keep-alive\r\n\r\n"
    } else {
        b"connection: close\r\n\r\n"
    });
    out
}

/// Build a `SO_REUSEPORT` TCP listener (std) for a monoio runtime to adopt via
/// [`TcpListener::from_std`]. One independent socket is created PER worker so the
/// kernel load-balances accepts across the per-core runtimes (mirrors the
/// epoll-path `server::make_reuseport_listener`).
fn reuseport_std_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// Phase-1 substrate smoke entrypoint: boot one monoio io_uring runtime per
/// worker thread, each adopting its own `SO_REUSEPORT` listener on `addr`, and
/// serve a fixed HTTP/1.1 stub over io_uring. Blocks forever (joins the per-core
/// threads). Reachable via the gated `HJ_URING_SMOKE=<addr>` dev hook in `main`.
pub(crate) fn serve_smoke(addr: SocketAddr, workers: usize) -> io::Result<()> {
    let workers = workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for core in 0..workers {
        // Each thread gets its OWN reuseport socket (built on this thread so the
        // fd is owned per core), then adopts it into a per-core io_uring runtime.
        let std_listener = reuseport_std_listener(addr)?;
        let handle = std::thread::Builder::new()
            .name(format!("hj-uring-{core}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || per_core(core, std_listener))?;
        handles.push(handle);
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// One core's runtime for the SMOKE stub: a monoio io_uring runtime running an
/// accept loop that spawns a per-connection task. (The production transports
/// pin their per-core threads via `maybe_pin_core_thread` (#296); the smoke
/// stub stays unpinned.)
fn per_core(core: usize, std_listener: std::net::TcpListener) {
    let mut rt = build_core_runtime().expect("build monoio io_uring runtime");
    rt.block_on(async move {
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(core, error = %e, "uring: adopt reuseport listener failed");
                return;
            }
        };
        tracing::info!(core, "uring: per-core runtime serving");
        loop {
            crate::memtrim::collect_if_requested_on_thread();
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    // Local (per-core) spawn — share-nothing, no cross-core handoff.
                    monoio::spawn(handle_h1(stream));
                }
                Err(e) => tracing::debug!(core, error = %e, "uring: accept failed"),
            }
        }
    });
}

/// Outcome of trying to parse one request head out of the accumulated bytes.
enum Parsed {
    /// (method, path, head_len, content_length, keep_alive)
    Done(String, String, usize, usize, bool),
    Partial,
    Bad,
}

/// Real HTTP/1.1 connection handler over the monoio io_uring owned-buffer
/// read/write path: parse each request head with `httparse`, honor keep-alive +
/// Content-Length, support pipelining (retain bytes past the consumed request),
/// and write a real `Content-Length` response. This smoke handler intentionally
/// echoes the parsed method+path; production H1 uses `handle_h1_bridged`, which
/// dispatches through the tokio pipeline bridge.
async fn handle_h1(mut stream: TcpStream) {
    const MAX_HEAD: usize = 64 * 1024;
    let mut acc: Vec<u8> = Vec::with_capacity(8192);
    loop {
        // Parse a complete request head from `acc`, reading more as needed. The
        // parse borrows `acc`, so it is scoped in a block that drops the borrow
        // BEFORE we mutate `acc` (read more / drain the consumed request).
        let parsed = loop {
            let step = {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&acc) {
                    Ok(httparse::Status::Complete(head_len)) => {
                        let method = req.method.unwrap_or("GET").to_string();
                        let path = req.path.unwrap_or("/").to_string();
                        let http10 = req.version == Some(0);
                        let mut content_length = 0usize;
                        let mut conn_close = http10; // HTTP/1.0 defaults to close
                        for h in req.headers.iter() {
                            if h.name.eq_ignore_ascii_case("content-length") {
                                content_length = std::str::from_utf8(h.value)
                                    .ok()
                                    .and_then(|s| s.trim().parse().ok())
                                    .unwrap_or(0);
                            } else if h.name.eq_ignore_ascii_case("connection") {
                                if h.value.eq_ignore_ascii_case(b"close") {
                                    conn_close = true;
                                } else if h.value.eq_ignore_ascii_case(b"keep-alive") {
                                    conn_close = false;
                                }
                            }
                        }
                        Parsed::Done(method, path, head_len, content_length, !conn_close)
                    }
                    Ok(httparse::Status::Partial) => Parsed::Partial,
                    Err(_) => Parsed::Bad,
                }
            };
            match step {
                Parsed::Done(m, p, hl, cl, ka) => break Parsed::Done(m, p, hl, cl, ka),
                Parsed::Bad => return,
                Parsed::Partial => {
                    if acc.len() > MAX_HEAD {
                        return; // header block too large
                    }
                    let (res, chunk) = stream.read(vec![0u8; 8192]).await;
                    match res {
                        Ok(0) | Err(_) => return, // EOF / error
                        Ok(n) => acc.extend_from_slice(&chunk[..n]),
                    }
                }
            }
        };
        let Parsed::Done(method, path, head_len, content_length, keep_alive) = parsed else {
            return;
        };
        // Make sure the full body is buffered, then drop this request from `acc`
        // (any trailing bytes are the next pipelined request).
        let total = head_len.saturating_add(content_length);
        while acc.len() < total {
            let (res, chunk) = stream.read(vec![0u8; 8192]).await;
            match res {
                Ok(0) | Err(_) => return,
                Ok(n) => acc.extend_from_slice(&chunk[..n]),
            }
        }
        acc.drain(..total);

        let body = format!("ok {method} {path}\n");
        let conn = if keep_alive { "keep-alive" } else { "close" };
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: {}\r\n\r\n{}",
            body.len(),
            conn,
            body,
        );
        let (res, _b) = stream.write_all(resp.into_bytes()).await;
        if res.is_err() || !keep_alive {
            let _ = stream.shutdown().await;
            return;
        }
    }
}

/// Phase-3 H2 smoke: per-core monoio io_uring runtimes serving **HTTP/2 (h2c)**
/// via hj-h2's `serve_local` with a fixed echo service. Reachable via the gated
/// `HJ_URING_H2_SMOKE=<addr>` dev hook. Proves H2 framing over io_uring end-to-end.
pub(crate) fn serve_h2_smoke(addr: SocketAddr, workers: usize) -> io::Result<()> {
    let workers = workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for core in 0..workers {
        let std_listener = reuseport_std_listener(addr)?;
        let handle = std::thread::Builder::new()
            .name(format!("hj-uring-h2-{core}"))
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES)
            .spawn(move || per_core_h2(core, std_listener))?;
        handles.push(handle);
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

fn per_core_h2(core: usize, std_listener: std::net::TcpListener) {
    let mut rt = build_core_runtime().expect("build monoio io_uring runtime");
    rt.block_on(async move {
        let listener = match TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(core, error = %e, "uring h2: adopt reuseport listener failed");
                return;
            }
        };
        tracing::info!(core, "uring h2: per-core runtime serving");
        loop {
            crate::memtrim::collect_if_requested_on_thread();
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    monoio::spawn(handle_h2(stream));
                }
                Err(e) => tracing::debug!(core, error = %e, "uring h2: accept failed"),
            }
        }
    });
}

/// h2c connection handler: drive hj-h2's monoio `serve_local` with a fixed echo
/// service (immediate handler — suits the sequential monoio loop).
async fn handle_h2(stream: TcpStream) {
    if let Err(e) =
        hj_h2::server::serve_local(stream, h2_service, hj_h2::server::Config::default()).await
    {
        tracing::debug!(error = %e, "uring h2: connection ended");
    }
}

/// The fixed H2 service for the monoio (`serve_local`) h2c smoke handler.
fn h2_service(_req: hj_core::Request) -> impl std::future::Future<Output = hj_core::Response> {
    async { hj_core::text_response(http::StatusCode::OK, "httpjet-uring-h2\n") }
}

/// One read into the CONNECTION-OWNED scratch (reused across every read of the
/// connection — monoio's rent API hands the Vec back after each op). Previously this
/// allocated a fresh 8 KiB Vec per read, including each idle keep-alive timeout tick.
/// Returns the number of bytes read; data lands in `scratch[..n]`.
async fn read_timeout<S>(
    stream: &mut S,
    timeout: Option<std::time::Duration>,
    scratch: &mut Vec<u8>,
) -> io::Result<usize>
where
    S: monoio::io::AsyncReadRent,
{
    scratch.clear();
    if scratch.capacity() == 0 {
        scratch.reserve(8192);
    }
    let buf = std::mem::take(scratch);
    match timeout {
        Some(d) => match monoio::time::timeout(d, stream.read(buf)).await {
            Ok((Ok(n), b)) => {
                *scratch = b;
                Ok(n)
            }
            // The rented buffer died with the timed-out future; the next read re-reserves.
            Ok((Err(e), _)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out")),
        },
        None => {
            let (res, b) = stream.read(buf).await;
            *scratch = b;
            res
        }
    }
}

#[cfg(test)]
mod chunked_tests {
    use super::codec::*;
    use super::*;

    /// (#334) The monoio-fork multishot accept: one armed SQE yields every
    /// inbound connection; peer addrs come from getpeername (multishot CQEs
    /// carry no sockaddr); dropping the stream cancels the armed SQE without
    /// disturbing the listener or panicking the runtime teardown.
    #[test]
    fn multishot_accept_stream_accepts_many() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let mut rt = build_core_runtime().unwrap();
        rt.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let mut accepts = listener.accept_multi().unwrap();
            let clients = std::thread::spawn(move || {
                (0..5)
                    .map(|_| std::net::TcpStream::connect(addr).unwrap())
                    .collect::<Vec<_>>()
            });
            for _ in 0..5 {
                let conn = accepts
                    .next()
                    .await
                    .expect("multishot terminated early")
                    .expect("accept failed");
                let peer = conn.peer_addr().expect("getpeername");
                assert!(peer.ip().is_loopback());
            }
            drop(accepts);
            // The listener still works single-shot after the stream detaches.
            let extra = std::thread::spawn(move || std::net::TcpStream::connect(addr).unwrap());
            let (conn, peer) = listener.accept().await.expect("single-shot after detach");
            assert!(peer.ip().is_loopback());
            drop(conn);
            let _ = extra.join().unwrap();
            let _ = clients.join().unwrap();
        });
    }

    #[test]
    fn listener_readiness_requires_every_worker_acknowledgement() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(())).unwrap();
        tx.send(Ok(())).unwrap();
        drop(tx);
        assert!(
            wait_for_worker_readiness_with_timeout(
                "test",
                2,
                rx,
                std::time::Duration::from_millis(10)
            )
            .is_ok()
        );
    }

    #[test]
    fn listener_readiness_fails_on_worker_error_or_early_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Err("adopt failed".to_owned())).unwrap();
        drop(tx);
        assert!(
            wait_for_worker_readiness_with_timeout(
                "test",
                1,
                rx,
                std::time::Duration::from_millis(10)
            )
            .is_err()
        );

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(())).unwrap();
        drop(tx);
        assert!(
            wait_for_worker_readiness_with_timeout(
                "test",
                2,
                rx,
                std::time::Duration::from_millis(10)
            )
            .is_err()
        );
    }

    const WS_REQUEST: &[u8] = b"GET /echo HTTP/1.1\r\n\
Host: localhost\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n";

    fn websocket_test_core() -> (tokio::runtime::Runtime, CoreHandler) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let state = runtime.block_on(async {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "httpjet-uring-ws-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(root.join("logs")).unwrap();
            let mut config = hj_core::config::ServerConfig::default();
            config.server_root = root;
            config.tuning.max_keep_alive_req = 1;
            crate::state::ServerState::new(
                Arc::new(config),
                None,
                None,
                None,
                Arc::new(hj_compress::PageDictRegistry::empty()),
                1,
                crate::state::XfCapsuleConfig::disabled(),
                None,
                false,
                None,
                false,
                crate::state::RewriteTuning::default(),
            )
        });
        let bridge = bridge::spawn_bridge(1, |mut req: hj_core::Request, _ctx| async move {
            if req.uri().path() == "/reject" {
                return http::Response::builder()
                    .status(http::StatusCode::FORBIDDEN)
                    .body(hj_core::Body::Full(bytes::Bytes::from_static(b"rejected")))
                    .unwrap();
            }

            let handoff = req
                .extensions_mut()
                .remove::<bridge::UringUpgradeRequest>()
                .expect("io_uring upgrade extension");
            let (to_upstream, mut inbound) = tokio::sync::mpsc::channel(8);
            let (outbound, from_upstream) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                while let Some(bytes) = inbound.recv().await {
                    if outbound.send(Ok(bytes)).await.is_err() {
                        break;
                    }
                }
            });
            assert!(
                handoff
                    .handoff(bridge::UringUpgradeIo {
                        to_upstream,
                        from_upstream,
                    })
                    .await
                    .is_ok(),
                "upgrade handoff"
            );
            http::Response::builder()
                .status(http::StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::CONNECTION, "Upgrade")
                .header(http::header::UPGRADE, "websocket")
                .header("sec-websocket-accept", "answer")
                .body(hj_core::Body::Empty)
                .unwrap()
        })
        .unwrap();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        (
            runtime,
            CoreHandler {
                bridge,
                holder,
                listener_name: Arc::from("test"),
            },
        )
    }

    fn read_h1_head(reader: &mut impl std::io::Read) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            reader.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024, "response head did not terminate");
        }
        head
    }

    fn websocket_client(mut stream: impl std::io::Read + std::io::Write, prefix: &[u8]) {
        let mut initial = WS_REQUEST.to_vec();
        initial.extend_from_slice(prefix);
        stream.write_all(&initial).unwrap();
        stream.flush().unwrap();

        let head = read_h1_head(&mut stream);
        let text = String::from_utf8(head).unwrap().to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 101 switching protocols\r\n"));
        assert!(text.contains("connection: upgrade\r\n"));
        assert!(text.contains("upgrade: websocket\r\n"));

        let mut echoed = vec![0u8; prefix.len()];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, prefix);
        stream.write_all(b"second-frame").unwrap();
        stream.flush().unwrap();
        let mut echoed = [0u8; 12];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"second-frame");
    }

    /// Decode `buf[start..]` in one shot (whole body already present).
    fn decode_all(buf: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
        let mut dec = ChunkedDecoder::new(start);
        match dec.advance(buf) {
            ChunkStep::Done(end) => Some((std::mem::take(&mut dec.body), end)),
            _ => None,
        }
    }

    #[test]
    fn keepalive_cap_closes_after_n_requests() {
        // 0 = unlimited: never exhausted, however many served.
        assert!(!keepalive_exhausted(1, 0));
        assert!(!keepalive_exhausted(10_000, 0));
        // max=N: serve exactly N (close on the Nth response), not before.
        assert!(!keepalive_exhausted(1, 3));
        assert!(!keepalive_exhausted(2, 3));
        assert!(
            keepalive_exhausted(3, 3),
            "Nth request must close (off-by-one guard)"
        );
        assert!(keepalive_exhausted(4, 3));
        // max=1: close immediately after the first request.
        assert!(keepalive_exhausted(1, 1));
    }

    #[test]
    fn shared_connection_permit_is_atomic_and_released_on_drop() {
        use std::sync::atomic::Ordering;

        let active = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let attempts: Vec<_> = (0..16)
            .map(|_| {
                let active = active.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ConnectionPermit::try_acquire(active, 1)
                })
            })
            .collect();
        let mut permits: Vec<_> = attempts
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(permits.iter().filter(|permit| permit.is_some()).count(), 1);
        assert_eq!(active.load(Ordering::Relaxed), 1);
        permits.clear();
        assert_eq!(active.load(Ordering::Relaxed), 0);
        let permit = ConnectionPermit::try_acquire(active.clone(), 1).unwrap();
        assert_eq!(active.load(Ordering::Relaxed), 1);
        drop(permit);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn expect_100_continue_detection() {
        assert!(expect_is_100_continue(b"100-continue"));
        assert!(expect_is_100_continue(b"100-Continue"));
        assert!(expect_is_100_continue(b"  100-continue  ")); // OWS-trimmed
        assert!(!expect_is_100_continue(b"100-continue-extra"));
        assert!(!expect_is_100_continue(b"")); // no expectation
        assert!(!expect_is_100_continue(b"continue"));
    }

    fn padded_request_head(len: usize) -> Vec<u8> {
        let prefix = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ";
        let suffix = b"\r\n\r\n";
        assert!(len >= prefix.len() + suffix.len());
        let mut head = Vec::with_capacity(len);
        head.extend_from_slice(prefix);
        head.resize(len - suffix.len(), b'a');
        head.extend_from_slice(suffix);
        head
    }

    fn segmented_head_progress(wire: &[u8], max_head: usize, chunk: usize) -> RequestHeadProgress {
        let mut buffered = Vec::new();
        for part in wire.chunks(chunk.max(1)) {
            buffered.extend_from_slice(part);
            let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
            let mut request = httparse::Request::new(&mut headers);
            let progress =
                request_head_progress(request.parse(&buffered), buffered.len(), max_head);
            if progress != RequestHeadProgress::Partial {
                return progress;
            }
        }
        RequestHeadProgress::Partial
    }

    #[test]
    fn request_head_limit_is_exact_and_segmentation_independent() {
        const LIVE_MAX: usize = 16_380;
        let exact = padded_request_head(LIVE_MAX);
        let over = padded_request_head(LIVE_MAX + 1);
        for chunk in [1, 7, 8192, LIVE_MAX, LIVE_MAX + 1] {
            assert_eq!(
                segmented_head_progress(&exact, LIVE_MAX, chunk),
                RequestHeadProgress::Complete(LIVE_MAX),
                "exact boundary, chunk={chunk}"
            );
            assert_eq!(
                segmented_head_progress(&over, LIVE_MAX, chunk),
                RequestHeadProgress::TooLarge,
                "limit + 1, chunk={chunk}"
            );
        }
    }

    #[test]
    fn te_is_chunked_only_for_lone_chunked() {
        assert!(te_is_chunked(b"chunked"));
        assert!(te_is_chunked(b"  Chunked "));
        assert!(!te_is_chunked(b"gzip, chunked")); // compound -> rejected, not framed
        assert!(!te_is_chunked(b"gzip"));
        assert!(!te_is_chunked(b""));
    }

    #[test]
    fn parse_chunk_size_handles_hex_and_extensions() {
        assert_eq!(parse_chunk_size(b"1a"), Some(26));
        assert_eq!(parse_chunk_size(b"0"), Some(0));
        assert_eq!(parse_chunk_size(b"FF;name=value"), Some(255));
        assert_eq!(parse_chunk_size(b""), None);
        assert_eq!(parse_chunk_size(b"zz"), None);
        // (#232 class) 1*HEXDIG only: from_str_radix would accept a leading '+'.
        assert_eq!(parse_chunk_size(b"+2"), None);
        // ASCII-OWS padding is fine; Unicode whitespace is not.
        assert_eq!(parse_chunk_size(b" 2 "), Some(2));
        assert_eq!(parse_chunk_size(b"\xc2\xa02"), None);
    }

    #[test]
    fn resolve_content_length_rejects_signed_padded_forms() {
        // (#232 + residual) digit-only after an ASCII-OWS trim: no '+', no obs-text.
        assert_eq!(
            resolve_content_length([b"5".as_slice()].into_iter()),
            Ok(Some(5))
        );
        assert_eq!(
            resolve_content_length([b" 7 ".as_slice()].into_iter()),
            Ok(Some(7))
        );
        assert_eq!(
            resolve_content_length([b"+5".as_slice()].into_iter()),
            Err(())
        );
        // U+00A0 (0xC2 0xA0) padding survives httparse header values but must not
        // be stripped by a Unicode-aware trim into a "valid" length.
        assert_eq!(
            resolve_content_length([b"\xc2\xa05".as_slice()].into_iter()),
            Err(())
        );
        assert_eq!(resolve_content_length([].into_iter()), Ok(None));
        assert_eq!(
            resolve_content_length([b"5".as_slice(), b"6".as_slice()].into_iter()),
            Err(()),
            "conflicting duplicates are unframable"
        );
    }

    #[test]
    fn single_chunk_round_trip() {
        let raw = b"5\r\nHELLO\r\n0\r\n\r\n";
        let (body, end) = decode_all(raw, 0).expect("decodes");
        assert_eq!(body, b"HELLO");
        assert_eq!(end, raw.len());
    }

    #[test]
    fn multiple_chunks_concatenate_in_order() {
        let raw = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n";
        let (body, end) = decode_all(raw, 0).expect("decodes");
        assert_eq!(body, b"abcdefg");
        assert_eq!(end, raw.len());
    }

    #[test]
    fn empty_chunked_body_is_zero_length() {
        let raw = b"0\r\n\r\n";
        let (body, end) = decode_all(raw, 0).expect("decodes");
        assert!(body.is_empty());
        assert_eq!(end, raw.len());
    }

    #[test]
    fn trailers_after_last_chunk_are_consumed() {
        let raw = b"5\r\nHELLO\r\n0\r\nX-Trailer: v\r\n\r\n";
        let (body, end) = decode_all(raw, 0).expect("decodes");
        assert_eq!(body, b"HELLO");
        assert_eq!(end, raw.len());
    }

    #[test]
    fn consumed_end_leaves_pipelined_bytes() {
        // A chunked request followed by the start of a pipelined GET.
        let raw = b"5\r\nHELLO\r\n0\r\n\r\nGET /next HTTP/1.1\r\n";
        let (body, end) = decode_all(raw, 0).expect("decodes");
        assert_eq!(body, b"HELLO");
        assert_eq!(&raw[end..], b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn decode_respects_a_nonzero_start_offset() {
        // Simulate the head sitting in front of the chunked body.
        let raw = b"POST / HTTP/1.1\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let start = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (body, end) = decode_all(raw, start).expect("decodes");
        assert_eq!(body, b"abc");
        assert_eq!(end, raw.len());
    }

    #[test]
    fn incremental_feeding_resumes_without_reparsing_data() {
        // Feed the buffer one byte at a time; the decoder must converge exactly once.
        let raw: &[u8] = b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n";
        let mut dec = ChunkedDecoder::new(0);
        let mut buf = Vec::new();
        let mut result = None;
        for &b in raw {
            buf.push(b);
            match dec.advance(&buf) {
                ChunkStep::Done(end) => {
                    result = Some((std::mem::take(&mut dec.body), end));
                    break;
                }
                ChunkStep::NeedMore => {}
                ChunkStep::Bad => panic!("unexpected Bad"),
            }
        }
        let (body, end) = result.expect("eventually completes");
        assert_eq!(body, b"abcdefg");
        assert_eq!(end, raw.len());
    }

    #[test]
    fn partial_buffer_returns_need_more_not_bad() {
        let mut dec = ChunkedDecoder::new(0);
        // Only the size line + part of the data is present.
        assert!(matches!(dec.advance(b"5\r\nHEL"), ChunkStep::NeedMore));
    }

    #[test]
    fn bad_hex_size_is_rejected() {
        let mut dec = ChunkedDecoder::new(0);
        assert!(matches!(dec.advance(b"zz\r\nabc\r\n"), ChunkStep::Bad));
    }

    #[test]
    fn missing_crlf_after_chunk_data_is_rejected() {
        let mut dec = ChunkedDecoder::new(0);
        // 3-byte chunk "abc" must be followed by CRLF; here it's "XX".
        assert!(matches!(
            dec.advance(b"3\r\nabcXX0\r\n\r\n"),
            ChunkStep::Bad
        ));
    }

    #[test]
    fn oversized_chunk_size_line_is_rejected() {
        let mut dec = ChunkedDecoder::new(0);
        let mut buf = vec![b'a'; MAX_CHUNK_LINE + 16]; // no CRLF, over the line cap
        buf.truncate(MAX_CHUNK_LINE + 16);
        assert!(matches!(dec.advance(&buf), ChunkStep::Bad));
    }

    #[test]
    fn chunked_decoder_rejects_when_raw_exceeds_cap() {
        // (U2) Endless-trailer / tiny-chunk-amplification guard: a body whose RAW bytes
        // exceed the budget is rejected even though every line is small and well-framed.
        let mut dec = ChunkedDecoder::new(0);
        dec.max_raw = 64;
        let mut buf = b"0\r\n".to_vec(); // last-chunk, then a long well-formed trailer run
        for _ in 0..40 {
            buf.extend_from_slice(b"X: y\r\n");
        }
        assert!(matches!(dec.advance(&buf), ChunkStep::Bad));
    }

    // ---- (U1) response-writer serialization ----
    #[test]
    fn serialize_head_omits_body_but_keeps_representation_length() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/html"),
        );
        let out = serialize_h1_response_head(http::StatusCode::OK, &h, 17, true, true);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("content-length: 17\r\n"),
            "advertises the GET length: {s}"
        );
        assert!(out.ends_with(b"\r\n\r\n"), "ends at the header terminator");
    }

    #[test]
    fn serialize_empty_head_advertises_handler_content_length_not_zero() {
        // (audit-2026-07-01) hj-static's HEAD contract returns `Body::Empty` + a real
        // `Content-Length`. The writer must advertise that representation length, not recompute
        // `content-length: 0` from the (deliberately empty) body — a HEAD of a 6-byte file must
        // still say `content-length: 6` (RFC 9110 §9.3.2).
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("6"),
        );
        let out = serialize_h1_response_head(http::StatusCode::OK, &h, 0, true, true);
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("content-length: 6\r\n"),
            "empty HEAD must advertise the handler's length, got: {s}"
        );
        assert!(
            !s.contains("content-length: 0\r\n"),
            "must not advertise 0 for a non-empty resource: {s}"
        );
        assert!(out.ends_with(b"\r\n\r\n"), "no body on the wire");
    }

    #[test]
    fn serialize_strips_hop_by_hop_and_overrides_backend_content_length() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive"),
        );
        h.insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_static("chunked"),
        );
        h.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("999"),
        ); // wrong
        h.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("text/plain"),
        );
        let out = serialize_h1_response_head(http::StatusCode::OK, &h, 5, false, true);
        let s = String::from_utf8_lossy(&out).to_ascii_lowercase();
        assert!(!s.contains("transfer-encoding"), "TE stripped: {s}");
        assert_eq!(
            s.matches("content-length:").count(),
            1,
            "one authoritative CL"
        );
        assert!(
            s.contains("content-length: 5\r\n"),
            "body.len() overrides backend 999: {s}"
        );
        assert_eq!(
            s.matches("connection:").count(),
            1,
            "only our connection header"
        );
        assert!(out.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn buffered_response_head_allocation_is_independent_of_body_size() {
        let head = serialize_h1_response_head(
            http::StatusCode::OK,
            &http::HeaderMap::new(),
            64 * 1024 * 1024,
            false,
            true,
        );
        assert!(
            head.capacity() < 1024,
            "body bytes must not be copied into the head"
        );
        assert!(String::from_utf8_lossy(&head).contains("content-length: 67108864\r\n"));
    }

    #[test]
    fn body_forbidden_statuses_have_headers_only_status_specific_framing() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "123".parse().unwrap());
        for (status, expected_length) in [
            (http::StatusCode::CONTINUE, None),
            (http::StatusCode::NO_CONTENT, None),
            (http::StatusCode::RESET_CONTENT, Some(0)),
            (http::StatusCode::NOT_MODIFIED, Some(123)),
        ] {
            let full = serialize_h1_response_head(status, &headers, 7, false, true);
            let streamed = serialize_h1_stream_head(status, &headers, Some(7), false, true);
            for wire in [&full, &streamed] {
                let text = String::from_utf8_lossy(wire).to_ascii_lowercase();
                assert!(!text.contains("transfer-encoding"), "{status}: {text}");
                match expected_length {
                    Some(n) => assert!(
                        text.contains(&format!("content-length: {n}\r\n")),
                        "{status}: {text}"
                    ),
                    None => assert!(!text.contains("content-length:"), "{status}: {text}"),
                }
                assert!(wire.ends_with(b"\r\n\r\n"), "{status}: headers only");
            }
        }
    }

    fn capture_h1_response(response: bridge::BridgeResp) -> Vec<u8> {
        use std::io::Read;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut wire = Vec::new();
            stream.read_to_end(&mut wire).unwrap();
            wire
        });
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(write_h1_response(&mut stream, response, false, false).await);
            let _ = stream.shutdown().await;
        });
        client.join().unwrap()
    }

    #[test]
    fn full_and_stream_writers_discard_forbidden_response_bodies() {
        let full = capture_h1_response(bridge::BridgeResp {
            status: http::StatusCode::NO_CONTENT,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Full(bytes::Bytes::from_static(b"full-sentinel")),
        });

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Ok(bytes::Bytes::from_static(b"stream-sentinel")))
            .unwrap();
        let streamed = capture_h1_response(bridge::BridgeResp {
            status: http::StatusCode::NO_CONTENT,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Stream { rx, len: Some(15) },
        });

        for wire in [&full, &streamed] {
            let text = String::from_utf8_lossy(wire).to_ascii_lowercase();
            assert!(text.starts_with("http/1.1 204 no content\r\n"));
            assert!(!text.contains("content-length"));
            assert!(!text.contains("transfer-encoding"));
            assert!(!text.contains("sentinel"));
            assert!(wire.ends_with(b"\r\n\r\n"));
        }
        assert!(tx.is_closed(), "the forbidden stream producer is cancelled");
    }

    #[test]
    fn chunked_stream_writer_preserves_wire_framing() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Ok(bytes::Bytes::from_static(b"chunk-data")))
            .unwrap();
        drop(tx);
        let wire = capture_h1_response(bridge::BridgeResp {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Stream { rx, len: None },
        });
        let split = wire
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let head = String::from_utf8_lossy(&wire[..split]).to_ascii_lowercase();
        assert!(head.contains("transfer-encoding: chunked\r\n"));
        assert_eq!(&wire[split..], b"a\r\nchunk-data\r\n0\r\n\r\n");
    }

    #[test]
    fn unknown_length_head_never_advertises_chunked_framing() {
        let headers = http::HeaderMap::new();
        let wire = serialize_h1_stream_head(http::StatusCode::OK, &headers, None, true, true);
        let text = String::from_utf8(wire).unwrap().to_ascii_lowercase();
        assert!(!text.contains("transfer-encoding"));
        assert!(!text.contains("content-length"));
    }

    #[test]
    fn serialize_websocket_upgrade_preserves_switch_headers_without_framing() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONNECTION, "upgrade".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert("sec-websocket-accept", "answer".parse().unwrap());
        headers.insert(http::header::CONTENT_LENGTH, "0".parse().unwrap());
        let wire = serialize_h1_upgrade_response(http::StatusCode::SWITCHING_PROTOCOLS, &headers);
        let text = String::from_utf8(wire).unwrap().to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 101 switching protocols\r\n"));
        assert!(text.contains("connection: upgrade\r\n"));
        assert!(text.contains("upgrade: websocket\r\n"));
        assert!(text.contains("sec-websocket-accept: answer\r\n"));
        assert!(!text.contains("content-length"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn h1_websocket_echo_preserves_buffered_prefix_over_plaintext() {
        use monoio::io::AsyncReadRent;

        let (_tokio_runtime, core) = websocket_test_core();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let prefix = b"buffered-first-frame";
        let client = std::thread::spawn(move || {
            let stream = std::net::TcpStream::connect(local).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            websocket_client(stream, prefix);
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (mut stream, peer) = listener.accept().await.unwrap();
            let expected = WS_REQUEST.len() + prefix.len();
            let mut buffered = Vec::with_capacity(expected);
            while buffered.len() < expected {
                let (result, chunk) = stream.read(vec![0u8; expected - buffered.len()]).await;
                let read = result.unwrap();
                assert!(read > 0);
                buffered.extend_from_slice(&chunk[..read]);
            }
            handle_h1_bridged(
                stream,
                buffered,
                BridgeCtx::plain(peer, local, Proto::Http1),
                core,
                CancellationToken::new(),
            )
            .await;
        });
        client.join().unwrap();
    }

    #[test]
    fn h1_websocket_echo_over_tls() {
        let (_tokio_runtime, core) = websocket_test_core();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = monoio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client_config = Arc::new(client_config);

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let prefix = b"tls-first-frame";
        let client = std::thread::spawn(move || {
            let socket = std::net::TcpStream::connect(local).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned();
            let connection = rustls::ClientConnection::new(client_config, name).unwrap();
            websocket_client(rustls::StreamOwned::new(connection, socket), prefix);
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tls_bridged(
                stream,
                peer,
                local,
                core,
                acceptor,
                false,
                None,
                CancellationToken::new(),
            )
            .await;
        });
        client.join().unwrap();
    }

    #[test]
    fn h1_websocket_non_switching_response_uses_normal_framing() {
        let (_tokio_runtime, core) = websocket_test_core();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(local).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let request = String::from_utf8_lossy(WS_REQUEST).replace("/echo", "/reject");
            use std::io::{Read, Write};
            stream.write_all(request.as_bytes()).unwrap();
            stream.flush().unwrap();
            let head = read_h1_head(&mut stream);
            let text = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(text.starts_with("http/1.1 403 forbidden\r\n"));
            assert!(text.contains("content-length: 8\r\n"));
            assert!(!text.contains("upgrade: websocket\r\n"));
            let mut body = [0u8; 8];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"rejected");
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (stream, peer) = listener.accept().await.unwrap();
            handle_h1_bridged(
                stream,
                Vec::new(),
                BridgeCtx::plain(peer, local, Proto::Http1),
                core,
                CancellationToken::new(),
            )
            .await;
        });
        client.join().unwrap();
    }

    #[test]
    fn serialize_preserves_non_visible_ascii_header_value() {
        let mut h = http::HeaderMap::new();
        // A byte > 0x7f is valid in an HeaderValue but fails to_str(); write it raw.
        h.insert(
            http::HeaderName::from_static("x-blob"),
            http::HeaderValue::from_bytes(b"caf\xc3\xa9").unwrap(),
        );
        let out = serialize_h1_response_head(http::StatusCode::OK, &h, 0, false, false);
        assert!(
            out.windows(5).any(|w| w == b"caf\xc3\xa9"),
            "raw header bytes preserved"
        );
    }

    #[test]
    fn resolve_content_length_strict_rejects_malformed_and_conflicting() {
        // (N1) malformed / overflow / conflicting-duplicate CL must be rejected, not coerced
        // to a short length (which would smuggle the trailing body bytes).
        fn r(xs: &[&[u8]]) -> Result<Option<usize>, ()> {
            resolve_content_length(xs.iter().copied())
        }
        assert_eq!(r(&[]), Ok(None)); // absent
        assert_eq!(r(&[b"4" as &[u8]]), Ok(Some(4)));
        assert_eq!(r(&[b" 0 " as &[u8]]), Ok(Some(0)));
        assert_eq!(r(&[b"4" as &[u8], b"4"]), Ok(Some(4))); // identical duplicates collapse
        assert_eq!(r(&[b"nope" as &[u8]]), Err(())); // non-numeric
        assert_eq!(r(&[b"99999999999999999999999999" as &[u8]]), Err(())); // overflow
        assert_eq!(r(&[b"4" as &[u8], b"0"]), Err(())); // conflicting duplicates
    }

    /// (#277) Differential coverage for the single-materialization intake: the
    /// same wire bytes that the old builder-based path classified must classify
    /// identically now that Method/Uri/HeaderMap are built once. Drives
    /// `materialize_head` directly (the pure core of the intake).
    #[test]
    fn materialize_head_preserves_framing_and_uri_rejection() {
        fn parse(wire: &[u8]) -> ParsedReq {
            let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(wire) {
                Ok(httparse::Status::Complete(head_len)) => materialize_head(&req, head_len),
                other => panic!("fixture must parse-complete, got {other:?}"),
            }
        }
        let done = |p: &ParsedReq| matches!(p, ParsedReq::Done { .. });
        let framing = |p: &ParsedReq| match p {
            ParsedReq::Done { framing, .. } => Some(*framing),
            _ => None,
        };

        // Plain GET: accepted, empty framing, keep-alive, Method/Uri/headers materialized.
        let p = parse(b"GET /a?b=c HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n");
        match &p {
            ParsedReq::Done {
                method,
                uri,
                headers,
                framing,
                keep_alive,
                ..
            } => {
                assert_eq!(method, http::Method::GET);
                assert_eq!(uri.path(), "/a");
                assert_eq!(uri.query(), Some("b=c"));
                assert_eq!(headers.get("host").unwrap(), "x");
                assert_eq!(headers.get("accept").unwrap(), "*/*");
                assert_eq!(*framing, BodyFraming::Length(0));
                assert!(*keep_alive);
            }
            ParsedReq::Bad => panic!("expected Done, got Bad"),
            _ => panic!("expected Done"),
        }

        // #233 class: an httparse-accepted target that http::Uri rejects → Bad (400+close),
        // NOT a Done that would panic downstream.
        assert!(matches!(
            parse(b"GET /a<b HTTP/1.1\r\nHost: x\r\n\r\n"),
            ParsedReq::Bad
        ));
        assert!(matches!(
            parse(b"GET /a`b HTTP/1.1\r\nHost: x\r\n\r\n"),
            ParsedReq::Bad
        ));

        // Duplicate Host → Reject (smuggling / routing ambiguity).
        assert_eq!(
            framing(&parse(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")),
            Some(BodyFraming::Reject)
        );

        // TE + CL together → Reject.
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
            )),
            Some(BodyFraming::Reject)
        );
        // Lone chunked → Chunked.
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            )),
            Some(BodyFraming::Chunked)
        );
        // Conflicting duplicate CL → Reject.
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"
            )),
            Some(BodyFraming::Reject)
        );
        // Well-formed CL → Length(n).
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n"
            )),
            Some(BodyFraming::Length(5))
        );

        // Connection: close in a multi-token list flips keep_alive off.
        match parse(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n") {
            ParsedReq::Done { keep_alive, .. } => assert!(!keep_alive),
            ParsedReq::Bad => panic!("expected Done, got Bad"),
            _ => panic!("expected Done"),
        }
        // Duplicate header names are preserved as multiple values (append, not insert).
        match parse(b"GET / HTTP/1.1\r\nHost: x\r\nX-H: 1\r\nX-H: 2\r\n\r\n") {
            ParsedReq::Done { headers, .. } => {
                let vals: Vec<_> = headers.get_all("x-h").iter().collect();
                assert_eq!(vals.len(), 2, "both X-H values retained");
            }
            ParsedReq::Bad => panic!("expected Done, got Bad"),
            _ => panic!("expected Done"),
        }
        assert!(done(&parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")));
    }
}
