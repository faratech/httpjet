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
#[cfg(test)]
mod generation_test;
pub(crate) mod h3;
#[cfg(feature = "ktls")]
pub(crate) mod ktls;
pub(crate) mod ktls_policy;
pub(crate) mod proxy_protocol;
mod proxy_protocol_wire;
mod qpack;
pub(crate) mod request_body;
#[cfg(test)]
mod tls_write_test;
mod unix_path;
pub(crate) mod worker_group;
mod write_watch;
pub(crate) use worker_group::WorkerGroup;

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use socket2::{Domain, Protocol, Socket, Type};

use crate::serving_generation::{RequestGeneration, ServingView};
use crate::state::ServerState;
use bridge::{Bridge, BridgeCtx};
use codec::{
    BodyFraming, ChunkStep, ChunkedDecoder, MAX_REQUEST_HEADERS, RequestHeadProgress,
    chunked_accounted_bytes, classify_framing, head_has_bare_lf, request_head_progress,
    te_is_chunked,
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

/// Per-listener accept-time options, resolved ONCE at spawn from THAT listener's
/// config entry. Never derived from a global scan over all listeners — one
/// listener's opt-in must not change another listener's accept protocol.
#[derive(Clone, Copy, Default)]
pub(crate) struct ListenerBinding {
    pub proxy_protocol: bool,
}

/// What each monoio connection handler needs to serve a request: the on-core
/// cache-hit fast path (`pipeline::fast_serve`, no runtime hop) plus the bridge to
/// the tokio side-runtime for everything the fast path declines (miss / dynamic).
/// `holder` follows compatible application generations, while retaining the
/// accepted connection's trust epoch. `listener_name` is the vhost routing key.
#[derive(Clone)]
pub(crate) struct CoreHandler {
    bridge: Bridge,
    holder: ServingView,
    listener_name: Arc<str>,
}

impl CoreHandler {
    fn pin_connection(&self) -> Self {
        Self {
            holder: self.holder.pin_connection(),
            ..self.clone()
        }
    }

    #[cfg(feature = "otel")]
    fn trace_request(
        &self,
        state: &ServerState,
        ctx: &BridgeCtx,
        req: &mut hj_core::Request,
    ) -> Option<crate::otel::RequestTrace> {
        if !crate::otel::enabled() {
            return None;
        }
        let direct_peer = !ctx.peer_unix
            && state
                .server
                .listeners
                .iter()
                .find(|l| l.name == self.listener_name.as_ref())
                .is_some_and(|l| !l.proxy_protocol);
        let parent = crate::otel::inbound_parent(req.headers_mut(), ctx.peer.ip(), direct_peer);
        let trace = crate::otel::RequestTrace::new(parent);
        req.extensions_mut()
            .insert(crate::otel::TransportContext(trace.context()));
        Some(trace)
    }

    async fn dispatch_h1(
        &self,
        state: Arc<ServerState>,
        mut ctx: BridgeCtx,
        req: hj_core::Request,
        upgrade: bool,
    ) -> Option<bridge::BridgeResp> {
        if !upgrade && let Some(response) = self.fast(&state, &ctx, &req).await {
            return Some(bridge::fast_response(response, ctx.direct_file_egress).await);
        }
        // Only a request that crosses to the Tokio runtime carries its selected
        // generation. Keep it in the bridge sideband so ordinary misses do not
        // allocate and hash an `http::Extensions` map.
        ctx.request_generation = Some(RequestGeneration(state));
        #[cfg(feature = "otel")]
        crate::otel::execution_path(false);
        self.bridge.dispatch(req, ctx).await
    }

    #[cfg(feature = "otel")]
    async fn dispatch_h2(
        &self,
        mut ctx: BridgeCtx,
        mut req: hj_core::Request,
    ) -> hj_core::Response {
        let state = self.holder.load_full();
        #[cfg(feature = "otel")]
        let trace = self.trace_request(&state, &ctx, &mut req);
        let future = async {
            if let Some(response) = self.fast(&state, &ctx, &req).await {
                return response;
            }
            ctx.request_generation = Some(RequestGeneration(state));
            #[cfg(feature = "otel")]
            crate::otel::execution_path(false);
            self.bridge.dispatch_response(req, ctx).await
        };
        #[cfg(feature = "otel")]
        if let Some(trace) = trace {
            let mut response = crate::otel::in_context(trace.context(), future).await;
            trace.response_head(response.status());
            response.extensions_mut().insert(trace.completion());
            return response;
        }
        future.await
    }

    /// Try the on-core cache-hit fast path; `Some(resp)` if served without the bridge.
    async fn fast(
        &self,
        st: &Arc<ServerState>,
        ctx: &BridgeCtx,
        req: &hj_core::Request,
    ) -> Option<hj_core::Response> {
        // Stamp Date here (insert-if-absent): the page cache strips the stored Date
        // expecting the serve boundary to re-add one, and the uring writers never do — the
        // tokio path stamps at server::stamp_date, this is its on-core fast-path twin.
        crate::pipeline::fast_serve(
            st,
            &self.listener_name,
            ctx.peer.ip(),
            ctx.local,
            ctx.peer.port(),
            ctx.is_tls,
            ctx.client_auth_requested,
            ctx.peer_unix,
            ctx.proto,
            ctx.tls.clone(),
            req,
        )
        .await
        .map(|response| {
            #[cfg(feature = "otel")]
            crate::otel::execution_path(true);
            hj_core::stamp_date(response)
        })
    }
}

/// Grace window for draining in-flight io_uring connections after the shutdown
/// signal: each per-core accept loop stops accepting, then waits up to this long
/// for live connections to finish (H1 closes idle keep-alives, H2 GOAWAYs + drains)
/// before the process exits. Mirrors the tokio path's bounded graceful shutdown.
pub(crate) const URING_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

#[cfg(all(test, feature = "otel"))]
mod otel_test;
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

/// (#1034) Once the shutdown signal arrives, how long a streamed response may wait on its
/// backend for the next chunk before it is ended (H1: close without the chunked
/// terminator; H2: RST_STREAM CANCEL; H3: stream reset). Without it one SSE or long-poll
/// body held its core — and so the successor's start — for the full
/// [`URING_DRAIN_GRACE`]. Two seconds is far beyond the gap between the chunks of a
/// progressively rendered page, while a cleanly drained core finishes in 0.1-0.5 s; a
/// response that keeps producing keeps the full grace. Also bounds a lingering close
/// still running when the signal arrives (#1036).
const SHUTDOWN_IDLE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Resolves [`SHUTDOWN_IDLE_GRACE`] after the shutdown signal.
async fn shutdown_grace_elapsed(shutdown: &CancellationToken) {
    shutdown.cancelled().await;
    monoio::time::sleep(SHUTDOWN_IDLE_GRACE).await;
}

/// The next chunk of a streamed response body (`Ok(None)` at its end). After the shutdown
/// signal a body that waits [`SHUTDOWN_IDLE_GRACE`] for a chunk is abandoned with
/// `Err(())`; `stopping` latches the signal across calls (#1034).
async fn next_stream_chunk<T>(
    rx: &mut tokio::sync::mpsc::Receiver<T>,
    shutdown: &CancellationToken,
    stopping: &mut bool,
) -> Result<Option<T>, ()> {
    if !*stopping {
        monoio::select! {
            biased;
            item = rx.recv() => return Ok(item),
            _ = shutdown.cancelled() => *stopping = true,
        }
    }
    monoio::time::timeout(SHUTDOWN_IDLE_GRACE, rx.recv())
        .await
        .map_err(|_| ())
}

/// (#1036) A lingering close stops after this long even if the peer keeps sending.
const LINGER_TIME: std::time::Duration = std::time::Duration::from_secs(5);
/// (#1036) ... or once this many unread bytes were discarded. An over-cap Content-Length
/// is refused before any body byte is read, so the whole upload is still in flight; the
/// cap covers a typical overage (the regression test sends 10 MiB) while keeping a fast
/// sender from using the drain as a sink. Discarding is plain reads into one buffer.
const LINGER_MAX_BYTES: usize = 16 * 1024 * 1024;

/// (#1036) Lingering close, as nginx `lingering_close` and Apache `ap_lingering_close`:
/// half-close, then discard input until the peer's EOF before the socket is dropped.
/// Closing with unread input makes the kernel answer with a RST, and a client still
/// sending its body (it reads only after its upload) then loses the response it has not
/// read yet: ECONNRESET, or a 502/520 behind a proxy. Bounded by [`LINGER_TIME`],
/// [`LINGER_MAX_BYTES`] and [`SHUTDOWN_IDLE_GRACE`] after the shutdown signal.
async fn lingering_close<S>(stream: &mut S, shutdown: &CancellationToken)
where
    S: AsyncReadRent + AsyncWriteRent,
{
    if stream.shutdown().await.is_err() {
        return;
    }
    let deadline = std::time::Instant::now() + LINGER_TIME;
    let mut scratch = Vec::with_capacity(64 * 1024);
    let discard = async {
        let mut discarded = 0usize;
        while discarded < LINGER_MAX_BYTES {
            match read_before_deadline(stream, Some(deadline), &mut scratch).await {
                Ok(n) if n > 0 => discarded += n,
                _ => break,
            }
        }
    };
    monoio::select! {
        _ = discard => {}
        _ = shutdown_grace_elapsed(shutdown) => {}
    }
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
    mut accept_stopped: worker_group::AcceptRetirement,
    raced: Option<flume::Receiver<std::net::TcpStream>>,
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
    // chunks at latency bound even when traffic stops mid-chunk. It sleeps only
    // while a chunk is pending — an idle core is never woken by it.
    thread_local! {
        static CHUNK_TICKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if !CHUNK_TICKER.with(|t| t.replace(true)) {
        let ticker_shutdown = shutdown.clone();
        monoio::spawn(async move {
            loop {
                monoio::select! {
                    _ = ticker_shutdown.cancelled() => break,
                    _ = crate::pipeline::access_chunk_pending() => {}
                }
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
        // The default multishot path does not allocate a cancellation handle
        // per accepted connection; only the single-shot fallback needs one.
        let single_canceller = std::cell::RefCell::new(None);
        let mut next = std::pin::pin!(async {
            if let Some(queued) = &raced {
                if let Ok(stream) = queued.try_recv() {
                    let peer = stream.peer_addr()?;
                    return TcpStream::from_std(stream).map(|stream| (stream, peer));
                }
            }
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
                    None => {
                        let canceller = monoio::io::Canceller::new();
                        let cancel_handle = canceller.handle();
                        *single_canceller.borrow_mut() = Some(canceller);
                        return listener.cancelable_accept(cancel_handle).await;
                    }
                }
            }
        });
        monoio::select! {
            biased;
            _ = shutdown.cancelled() => {
                let pending = single_canceller.borrow_mut().take();
                if let Some(canceller) = pending {
                    // Keep the accept future alive through cancellation. Dropping
                    // it would leave kernel completion/descriptor cleanup pending
                    // while the successor starts consuming this accept queue.
                    canceller.cancel();
                    if let Ok((stream, _)) = next.await {
                        transfer_accepted(&accept_stopped, stream);
                    }
                }
                break;
            },
            accepted = &mut next => {
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
                        // Keepalive persists across an h1->WebSocket upgrade (same fd), so a
                        // relay whose client peer silently vanishes is reaped instead of parking
                        // its read forever. The tokio accept path armed this until server.rs was
                        // removed; the systemd listener sets KeepAlive=no, so nothing is
                        // inherited. Probe count stays at the OS default.
                        let _ = stream.set_tcp_keepalive(
                            Some(hj_proxy::PROXY_KEEPALIVE_IDLE),
                            Some(hj_proxy::PROXY_KEEPALIVE_INTERVAL),
                            None,
                        );
                        // Keepalive only covers an idle peer. A peer that stops reading
                        // while we have data in flight (zero-window probes forever) would
                        // otherwise park a write — and every response it pins — with no
                        // timer able to fire; the kernel aborts it after this bound.
                        let _ = stream.set_tcp_user_timeout(Some(tcp_user_timeout(&state)));
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
                    Err(e) => {
                        tracing::debug!(core = core_idx, secure, error = %e, "uring accept failed");
                        accept_error_backoff(&e).await;
                    }
                }
            }
        }
    }
    // Stop the kernel accept SQE before waiting on existing responses. Merely
    // breaking the user-space loop leaves a multishot accept armed throughout
    // the drain, consuming connections from a socket a successor may inherit.
    if let Some(accepts) = multi.as_mut() {
        accepts.cancel();
        while let Some(completion) = accepts.next().await {
            if let Ok(stream) = completion {
                transfer_accepted(&accept_stopped, stream);
            }
        }
    }
    drop(multi);
    drop(listener);
    if let Some(queued) = raced {
        for stream in queued.try_iter() {
            accept_stopped.transfer(stream);
        }
    }
    accept_stopped.cancel();
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
    // The flush ticker stopped with the shutdown signal, but connections answered
    // fast-path requests while draining: ship their buffered access lines.
    crate::pipeline::flush_access_chunks();
}

/// A resource error (EMFILE/ENFILE/ENOBUFS/ENOMEM) persists while the connection
/// waits in the backlog; resubmitting at once would spin the serving core (#685).
async fn accept_error_backoff(e: &io::Error) {
    if !accept_error_is_transient(e) {
        monoio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn accept_error_is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    )
}

fn transfer_accepted(retirement: &worker_group::AcceptRetirement, stream: TcpStream) {
    use std::os::fd::{FromRawFd, IntoRawFd};
    // No read/write operation has been issued on a just-accepted stream. Taking
    // its sole fd owner detaches it from this monoio runtime before thread transfer.
    let stream = unsafe { std::net::TcpStream::from_raw_fd(stream.into_raw_fd()) };
    retirement.transfer(stream);
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
        )
        .expect("bridge ServerState construction is config-validated upstream");
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let admission = pipeline_admission(holder.clone());
        let http_workers = spawn_uring_http(
            holder,
            listener_name,
            http_addr,
            workers,
            None,
            admission,
            ListenerBinding::default(),
        )?;
        http_workers.activate();
        // Keep this runtime alive to drive the bridge; the monoio cores run independently.
        std::future::pending::<()>().await;
        Ok::<(), anyhow::Error>(())
    })
}

/// Spawn the io_uring plaintext-HTTP transport: a cross-runtime bridge on the
/// CURRENT tokio runtime (each request loads the live `ServerState` generation
/// from `holder`, so SIGHUP reloads are honored) + one pinned-core monoio
/// io_uring runtime per worker, each adopting its own `SO_REUSEPORT` socket. The
/// returned group owns the monoio threads and stops/joins them on drop; success
/// means every core has acknowledged readiness, but none accepts traffic until
/// the caller activates the group. Shared by `serve` (full
/// state) and the `serve_uring` smoke hook (minimal state).
pub(crate) fn spawn_uring_http(
    holder: impl Into<ServingView>,
    listener_name: Arc<str>,
    http_addr: SocketAddr,
    workers: usize,
    inherited: Option<Vec<std::net::TcpListener>>,
    admission: bridge::BridgeAdmission,
    binding: ListenerBinding,
) -> anyhow::Result<WorkerGroup> {
    let holder = holder.into();
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
    let mut group = WorkerGroup::for_tcp_epoch(
        &shutdown,
        core.holder.trust_epoch(),
        worker_group::TcpListenerId {
            name: core.listener_name.clone(),
            tls: false,
        },
    );
    for (core_i, std_listener) in listeners.into_iter().enumerate() {
        let core = core.clone();
        let active_conns = active_conns.clone();
        let ready = ready_tx.clone();
        let activation = group.activation_gate();
        let accept_stopped = group.register_acceptor(&std_listener)?;
        group.spawn(
            std::thread::Builder::new()
                .name(format!("hj-uring-{core_i}"))
                .stack_size(crate::RUNTIME_THREAD_STACK_BYTES),
            move |shutdown| {
                maybe_pin_core_thread(core_i, worker_count);
                per_core_bridged(
                    core_i,
                    std_listener,
                    http_addr,
                    core,
                    shutdown,
                    active_conns,
                    ready,
                    activation,
                    binding,
                    accept_stopped,
                )
            },
        )?;
    }
    drop(ready_tx);
    wait_for_worker_readiness("HTTP", worker_count, ready_rx)?;
    Ok(group)
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
///
/// RING SIZE NEVER MOVES (#345): ring memory is charged against
/// RLIMIT_MEMLOCK for an unprivileged user — prod runs as nobody under the
/// unit's 8 MiB LimitMEMLOCK, where ~20 4096-entry rings (~400 KiB each)
/// BANKRUPT the budget and a late runtime fails to build at all. That was the
/// 2026-08-27 deploy crash-loop: the bridge runtime died at startup, cache
/// hits kept serving (on-core fast path) while every bridged request 502'd,
/// and readiness then took the process down. The build below therefore always
/// uses monoio's default 1024 entries.
pub(crate) fn build_core_runtime()
-> std::io::Result<monoio::Runtime<monoio::time::TimeDriver<monoio::IoUringDriver>>> {
    let mode = RING_MODE.load(std::sync::atomic::Ordering::Relaxed);
    if mode != RING_LEGACY {
        let mut urb = io_uring::IoUring::builder();
        urb.setup_coop_taskrun().setup_submit_all();
        if mode == RING_DEFER {
            urb.setup_single_issuer().setup_defer_taskrun();
        }
        let builder = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new().uring_builder(urb);
        match builder.enable_timer().build() {
            Ok(rt) => return Ok(rt),
            Err(error) => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(%error, mode, "uring: flagged ring build rejected; using plain default rings");
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
    if core >= libc::CPU_SETSIZE as usize {
        // available_parallelism() can exceed CPU_SETSIZE (1024) on pathological
        // hosts; CPU_SET would write past the fixed-size mask.
        return;
    }
    // SAFETY: a zeroed cpu_set_t is a valid empty mask; CPU_SET stays in
    // bounds (core < cpus and core < CPU_SETSIZE are both checked above); pid
    // 0 targets the calling thread.
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
    holder: impl Into<ServingView>,
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
    let view = holder.into();
    let body_budget = view.load_full().body_budget.clone();
    bridge::spawn_on_current_with_budget(admission, body_budget, move |req, mut ctx: BridgeCtx| {
        let state = ctx
            .request_generation
            .take()
            .map(|snapshot| snapshot.0)
            .unwrap_or_else(|| view.load_full());
        let lname = lname.clone();
        async move {
            // H1 already calls the same helper before bridging so it can retain
            // its historical refusal/connection semantics. H2/H3 arrive here
            // as one lease-backed full body; a second H1 pass is a no-op after
            // successful decoding removed Content-Encoding. Keep the decoder
            // future out of the common bridge task entirely: its codec state is
            // large, while an allocation on the explicitly encoded path is both
            // bounded and negligible beside decompression.
            let policy = state.request_decompression;
            let req = if request_body::needs_bridged_decompression(&req, policy) {
                match Box::pin(request_body::finish_bridged_request(
                    req,
                    &state.body_budget,
                    state.serve_config.max_req_body_size,
                    policy,
                ))
                .await
                {
                    Ok(req) => req,
                    Err(status) => {
                        return hj_core::stamp_date(
                            http::Response::builder()
                                .status(status)
                                .body(hj_core::Body::Empty)
                                .expect("static request-decompression response"),
                        );
                    }
                }
            } else {
                req
            };
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
                ctx.peer_unix,
                ctx.client_auth_requested,
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

/// A TLS listener's client-certificate policy (its `clientVerify`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ClientAuth {
    /// `clientVerify` 0 (or `--no-mtls`): no certificate is requested.
    #[default]
    None,
    /// 1 and 3: a certificate is requested and validated when presented; a peer
    /// without one is still served.
    Optional,
    /// 2: an external peer that presents no certificate is refused.
    Required,
}

impl ClientAuth {
    pub(crate) fn from_client_verify(client_verify: u8) -> Self {
        match client_verify {
            0 => ClientAuth::None,
            2 => ClientAuth::Required,
            _ => ClientAuth::Optional,
        }
    }

    pub(crate) fn for_listener(listener: &hj_core::config::Listener) -> Self {
        Self::from_client_verify(listener.tls.as_ref().map_or(0, |tls| tls.client_verify))
    }

    pub(crate) fn required(self) -> bool {
        self == ClientAuth::Required
    }

    /// A listener that asks for a certificate lets only a presented one vouch for
    /// forwarded client identity, whether or not it refuses peers without one.
    pub(crate) fn requested(self) -> bool {
        self != ClientAuth::None
    }
}

/// Spawn the io_uring HTTP/3 transport on `https_addr` (UDP): per-core monoio runtimes
/// driving quinn-proto, each dispatching requests through the SAME pipeline bridge as the
/// H1/H2 paths. This is the sole production H3 transport.
/// Must be called from within the ambient tokio runtime (the bridge receiver runs there).
pub(crate) fn spawn_uring_h3(
    holder: impl Into<ServingView>,
    listener_name: Arc<str>,
    https_addr: SocketAddr,
    workers: usize,
    rustls_cfg: Arc<rustls::ServerConfig>,
    client_auth: ClientAuth,
    inherited: Option<Vec<std::net::UdpSocket>>,
    admission: bridge::BridgeAdmission,
) -> anyhow::Result<(WorkerGroup, h3::QuicReloadHandle)> {
    let holder = holder.into();
    let shutdown = holder.load().shutdown.clone();
    let runtime = {
        let st = holder.load();
        let active_conns = st.metrics.active_conns.clone();
        drop(st);
        let serving_view = holder.clone();
        let config_holder = serving_view.clone();
        h3::H3RuntimeConfig::new(
            move || {
                let state = config_holder.load();
                (
                    h3::H3RequestConfig::new(
                        h3::H3RequestLimits::new(
                            state.serve_config.max_req_header_size,
                            state.serve_config.max_req_body_size,
                        ),
                        state.serve_config.header_read_timeout,
                    )
                    .with_body_ceiling(state.serve_config.request_body_ceiling),
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
        .with_serving_view(serving_view)
    };
    let bridge = build_pipeline_bridge(holder, listener_name, admission);
    let group = h3::serve_h3_pipeline(
        https_addr,
        workers,
        rustls_cfg,
        bridge,
        client_auth,
        runtime,
        inherited,
        shutdown,
    )?;
    Ok(group)
}

/// Spawn the io_uring TLS-HTTP transport on `https_addr`: one pinned-core monoio
/// runtime per worker, each adopting its own `SO_REUSEPORT` socket and terminating
/// TLS (rustls over monoio via monoio-rustls). After the handshake, ALPN selects
/// H1 vs H2 and the connection is served over the encrypted stream through the same
/// pipeline bridge. mTLS (clientVerify=2) is enforced at the application layer
/// exactly as the tokio path: a non-internal peer presenting no client cert is
/// refused post-handshake.
/// Returns a prepared group; call `activate` before expecting any handshake.
pub(crate) fn spawn_uring_https(
    holder: impl Into<ServingView>,
    listener_name: Arc<str>,
    https_addr: SocketAddr,
    workers: usize,
    tls_config: Arc<rustls::ServerConfig>,
    client_auth: ClientAuth,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    inherited: Option<Vec<std::net::TcpListener>>,
    admission: bridge::BridgeAdmission,
    binding: ListenerBinding,
) -> anyhow::Result<WorkerGroup> {
    let holder = holder.into();
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
    let mut group = WorkerGroup::for_tcp_epoch(
        &shutdown,
        core.holder.trust_epoch(),
        worker_group::TcpListenerId {
            name: core.listener_name.clone(),
            tls: true,
        },
    );
    for (core_i, std_listener) in listeners.into_iter().enumerate() {
        let core = core.clone();
        let active_conns = active_conns.clone();
        let acceptor: monoio_rustls::TlsAcceptor = tls_config.clone().into();
        let ktls_template = ktls_template.clone();
        let ready = ready_tx.clone();
        let activation = group.activation_gate();
        let accept_stopped = group.register_acceptor(&std_listener)?;
        group.spawn(
            std::thread::Builder::new()
                .name(format!("hj-uring-tls-{core_i}"))
                .stack_size(crate::RUNTIME_THREAD_STACK_BYTES),
            move |shutdown| {
                maybe_pin_core_thread(core_i, worker_count);
                per_core_https(
                    core_i,
                    std_listener,
                    https_addr,
                    core,
                    acceptor,
                    client_auth,
                    ktls_template,
                    shutdown,
                    active_conns,
                    ready,
                    activation,
                    binding,
                    accept_stopped,
                )
            },
        )?;
    }
    drop(ready_tx);
    wait_for_worker_readiness("HTTPS", worker_count, ready_rx)?;
    Ok(group)
}

/// rustls's largest outbound record allocation: a 16 KiB fragment plus the 5-byte
/// header, content type and 16-byte AEAD tag.
const TLS_RECORD_ALLOC: usize = 16 * 1024 + 5 + 1 + 16;

fn per_core_https(
    core_idx: usize,
    std_listener: std::net::TcpListener,
    local: SocketAddr,
    core: CoreHandler,
    acceptor: monoio_rustls::TlsAcceptor,
    client_auth: ClientAuth,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    shutdown: CancellationToken,
    _active_conns: Arc<std::sync::atomic::AtomicU64>,
    ready: WorkerReadyTx,
    activation: worker_group::ActivationGate,
    binding: ListenerBinding,
    accept_stopped: worker_group::AcceptRetirement,
) {
    let _record_classes = crate::memtrim::pin_size_classes(1024, TLS_RECORD_ALLOC);
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
        if ready.send(Ok(())).is_err() || !activation.wait().await {
            activation.retire_unstarted(accept_stopped, monoio::time::sleep(URING_DRAIN_GRACE)).await;
            return;
        }
        tracing::info!(core = core_idx, "uring tls: per-core runtime serving (H1/H2 over TLS → real pipeline)");
        accept_drain_loop(core_idx, listener, shutdown.clone(), true, core.clone(), accept_stopped, activation.raced_connections(), move |stream, peer| {
            let local = connection_local_addr(&stream, local);
            handle_tls_bridged(stream, peer, local, core.pin_connection(), acceptor.clone(), client_auth, ktls_template.clone(), shutdown.clone(), binding)
        })
        .await;
    });
}

/// Terminate TLS on a monoio io_uring connection, enforce mTLS, then serve H1/H2
/// (by ALPN) over the encrypted stream via the bridge. The connection metadata
/// (SNI, ALPN proto, SSL_* params, client-cert presence) is borrowed from the
/// rustls `ServerConnection`. Any decrypted post-handshake plaintext becomes the
/// handler prefix, while the TLS adapter and its raw-ciphertext read-ahead stay
/// intact across the direct-write I/O wrapper transition.
async fn handle_tls_bridged(
    mut stream: TcpStream,
    mut peer: SocketAddr,
    local: SocketAddr,
    core: CoreHandler,
    acceptor: monoio_rustls::TlsAcceptor,
    client_auth: ClientAuth,
    ktls_template: Option<Arc<hj_tls::KtlsConfigTemplate>>,
    shutdown: CancellationToken,
    binding: ListenerBinding,
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
    // (Tier 2) PROXY protocol: read the header from the raw stream and override the
    // peer address before the TLS handshake. Fail-closed: no header = close.
    if binding.proxy_protocol {
        if !state
            .server
            .listeners
            .iter()
            .find(|l| l.name == core.listener_name.as_ref())
            .is_some_and(|l| l.proxy_sender_allowed(peer.ip()))
        {
            tracing::debug!(%peer, "proxy_protocol: unauthorized transport peer; closing");
            return;
        }
        let header = monoio::select! {
            header = proxy_protocol::reader::read_and_strip(
                &mut stream,
                state.serve_config.header_read_timeout,
            ) => header,
            _ = shutdown.cancelled() => return,
        };
        match header {
            Ok(Some(h)) => {
                if let Some(src) = h.src {
                    tracing::debug!(real_peer = %src, "proxy_protocol: peer overridden");
                    peer = src;
                } else {
                    tracing::debug!(%peer, "proxy_protocol: peer preserved by LOCAL/UNKNOWN");
                }
            }
            _ => {
                tracing::debug!(%peer, "proxy_protocol: missing/malformed header; closing");
                return;
            }
        }
    }
    let handshake_timeout = state.serve_config.header_read_timeout;
    let handshake = async {
        match handshake_timeout {
            Some(d) => match monoio::time::timeout(d, acceptor.accept(stream)).await {
                Ok(Ok(t)) => Some(t),
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, %peer, "uring tls: handshake rejected");
                    None
                }
                Err(_) => {
                    tracing::debug!(%peer, "uring tls: handshake timed out");
                    None
                }
            },
            None => match acceptor.accept(stream).await {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "uring tls: handshake rejected");
                    None
                }
            },
        }
    };
    // (#1034) No request exists before the handshake completes: the shutdown signal
    // closes the connection instead of letting a silent peer hold the drain.
    let mut tls = monoio::select! {
        tls = handshake => match tls {
            Some(tls) => tls,
            None => return,
        },
        _ = shutdown.cancelled() => {
            tracing::debug!(%peer, "uring tls: shutdown before the handshake completed; closing");
            return;
        }
    };
    let sni: Option<Arc<str>> = tls.session().server_name().map(Arc::from);
    let proto = match tls.session().alpn_protocol() {
        Some(b"h2") => Proto::Http2,
        _ => Proto::Http1,
    };
    let has_client_cert = tls
        .session()
        .peer_certificates()
        .is_some_and(|c| !c.is_empty());
    // Full-vs-resumed split sizes the resumption win the client-verify
    // `NoServerSessions` posture forfeits (every CF-cycled origin connection is a
    // full handshake today). Counted once, at handshake completion.
    {
        use std::sync::atomic::Ordering;
        let m = core.holder.load();
        match tls.session().handshake_kind() {
            Some(rustls::HandshakeKind::Resumed) => {
                m.metrics
                    .tls_handshakes_resumed
                    .fetch_add(1, Ordering::Relaxed);
            }
            Some(kind) => {
                if kind == rustls::HandshakeKind::FullWithHelloRetryRequest {
                    m.metrics
                        .tls_handshakes_hello_retry
                        .fetch_add(1, Ordering::Relaxed);
                }
                m.metrics
                    .tls_handshakes_full
                    .fetch_add(1, Ordering::Relaxed);
            }
            None => {}
        }
    }
    let tls_params = hj_tls::tls_params_from_conn(tls.session());
    // Application-layer mTLS (clientVerify=2): refuse a non-internal peer that
    // presented no valid client cert — mirrors server.rs::mtls_refused exactly.
    // Client-auth listeners never resume sessions (hj-tls listener_session_storage),
    // so `peer_certificates` is always this handshake's own verifier verdict.
    if client_auth.required() && !has_client_cert && !hj_core::is_trusted_internal_peer(peer.ip()) {
        tracing::debug!(%peer, "uring tls: mTLS required, no client cert from non-internal peer; refusing");
        return;
    }
    // Drain any plaintext the client pipelined with the final handshake flight so it
    // is not lost when the stream is reconstructed (the prefix is handed to the
    // H1/H2 serve loop). Reads the already-decrypted buffer; no socket I/O.
    let mut prefix: Vec<u8> = Vec::new();
    {
        use std::io::Read;
        let mut reader = tls.session_mut().reader();
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
        direct_file_egress: false,
        peer_unix: false,
        client_auth_requested: client_auth.requested(),
        sni,
        tls: tls_params,
        request_generation: None,
        response_budget: bridge::connection_response_budget(),
    };

    // kTLS path: upgrade the socket to kernel-TLS and serve plaintext over the RAW fd
    // (kernel encrypts/decrypts). `prefix` carries the post-handshake plaintext we drained,
    // so the kernel RX resumes at the correct record sequence. TLS 1.3 only (different key
    // schedule + no KeyUpdate on 1.2 ⇒ a 1.2 connection just falls through to userspace).
    #[cfg(feature = "ktls")]
    if let Some(kl) = conn_key_log {
        let is_tls13 = tls.session().protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3);
        let suite = tls.session().negotiated_cipher_suite();
        if is_tls13 {
            // The kernel resumes at rustls's record sequence, so every record the
            // adapter already read must be decrypted here first; a buffered partial
            // record can only be finished in userspace.
            let drained = match tls.drain_received(&mut prefix) {
                Ok(drained) => drained,
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "uring ktls: post-handshake records rejected");
                    return;
                }
            };
            match (drained, kl.secrets(), suite) {
                (false, _, _) => {
                    tracing::debug!(%peer, "uring ktls: partial record buffered; serving via userspace TLS")
                }
                (true, Some((rx, tx)), Some(suite)) => {
                    // kTLS needs ownership of the raw socket and rustls connection to
                    // extract traffic secrets. Keep this destructive split confined to
                    // the committed kernel-TLS path; every userspace fallback retains
                    // the adapter's raw-ciphertext read-ahead via `map_io` below.
                    let (io, session) = tls.into_parts();
                    use std::os::fd::AsRawFd;
                    let fd = io.as_raw_fd();
                    // Read the true post-handshake record sequence for each direction (tickets
                    // already emitted advance TX; drained pipelined app-data advances RX) so the
                    // kernel keys are programmed at the right sequence. Consumes `session` —
                    // only on the committed kTLS path (the userspace fallback never extracts).
                    let (rx_seq, tx_seq) = match session.dangerous_extract_secrets() {
                        // A KeyUpdate processed during the handshake leaves rustls on keys
                        // the key log never recorded; the split already consumed the
                        // session, so close rather than program the kernel wrongly (#717).
                        Ok(s)
                            if ![(&s.rx.1, &rx), (&s.tx.1, &tx)]
                                .iter()
                                .all(|(cur, logged)| {
                                    ktls::traffic_key_iv(cur).is_some_and(|(k, iv)| {
                                        ktls::secret_derives(suite, logged, k, iv)
                                    })
                                }) =>
                        {
                            tracing::debug!(%peer, "uring ktls: traffic keys rotated during handshake; closing");
                            return;
                        }
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
                                    // Route every H2 write through KtlsWriteHalf so its
                                    // rekey gate serializes TX submission with a peer
                                    // KeyUpdate. The direct-fd writev shortcut bypasses
                                    // that gate and must not be used on kTLS streams.
                                    serve_h2_bridged(ks, prefix, ctx, core, shutdown, None).await
                                }
                                _ => {
                                    let mut ktls_ctx = ctx;
                                    ktls_ctx.direct_file_egress = true;
                                    handle_h1_bridged(
                                        ks,
                                        prefix,
                                        ktls_ctx,
                                        core,
                                        shutdown,
                                        Some(fd),
                                    )
                                    .await
                                }
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
    // rustls/aws-lc-rs still does the AEAD; this only changes the socket write. Mapping
    // the I/O in place is essential: the adapter may have read ciphertext beyond the
    // final handshake record which rustls has not consumed yet.
    let stream = tls.map_io(|io| directio::DirectWriteSocket::new_for(io, proto != Proto::Http2));
    match proto {
        Proto::Http2 => serve_h2_bridged(stream, prefix, ctx, core, shutdown, None).await,
        _ => handle_h1_bridged(stream, prefix, ctx, core, shutdown, None).await,
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
    activation: worker_group::ActivationGate,
    binding: ListenerBinding,
    accept_stopped: worker_group::AcceptRetirement,
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
        if ready.send(Ok(())).is_err() || !activation.wait().await {
            activation.retire_unstarted(accept_stopped, monoio::time::sleep(URING_DRAIN_GRACE)).await;
            return;
        }
        tracing::info!(core = core_idx, "uring serve: per-core runtime serving (H1/h2c → real pipeline)");
        accept_drain_loop(core_idx, listener, shutdown.clone(), false, core.clone(), accept_stopped, activation.raced_connections(), move |stream, peer| {
            let local = connection_local_addr(&stream, local);
            handle_conn_bridged(stream, peer, local, core.pin_connection(), shutdown.clone(), binding, false)
        })
        .await;
    });
}

/// Intake-buffer capacity a keep-alive connection may keep between requests.
const INTAKE_RETAIN_CAP: usize = 256 * 1024;

/// Right-size `acc` once a request body has been extracted from it. `drain` keeps the
/// body's peak capacity, which the body budget no longer charges; a client that always
/// pipelines a byte of its next request would otherwise pin it for the connection's life.
fn release_intake_capacity(acc: &mut Vec<u8>) {
    if acc.capacity() > INTAKE_RETAIN_CAP {
        let mut kept = Vec::with_capacity(acc.len().max(8192));
        kept.extend_from_slice(acc);
        *acc = kept;
    }
}

/// Remove a fixed-length request from the keep-alive accumulator without allocating a
/// second body-sized buffer. The body keeps `acc`'s existing allocation; only bytes for a
/// pipelined successor, when present, move into the replacement accumulator.
fn take_fixed_body(acc: &mut Vec<u8>, head_len: usize, body_len: usize) -> Vec<u8> {
    debug_assert!(head_len.saturating_add(body_len) <= acc.len());
    acc.drain(..head_len);
    if body_len == 0 {
        release_intake_capacity(acc);
        return Vec::new();
    }
    let pipelined = acc.split_off(body_len);
    let body = std::mem::replace(acc, pipelined);
    release_intake_capacity(acc);
    body
}

/// The accepted socket's own address when the listener is bound to a wildcard:
/// SERVER_ADDR / `%{SERVER_ADDR}` must name the interface the client reached
/// (as LiteSpeed reports it), never `0.0.0.0` / `::`.
fn connection_local_addr(stream: &TcpStream, bound: SocketAddr) -> SocketAddr {
    if !bound.ip().is_unspecified() {
        return bound;
    }
    stream
        .local_addr()
        .map(|a| SocketAddr::new(a.ip().to_canonical(), a.port()))
        .unwrap_or(bound)
}

/// h2c prior-knowledge connection preface (RFC 7540 §3.4). No HTTP/1.1 request
/// line can collide with it, so a prefix match is a safe protocol discriminator.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Sniff H1 vs the h2c prior-knowledge preface on a plaintext connection, then
/// route both through the bridge to the real pipeline. monoio streams aren't
/// peekable, so the discriminator bytes are read into `acc` and handed onward
/// (H1 reuses them as the head start; H2 seeds them as the preface prefix).
/// Serve one PLAINTEXT connection: PROXY-protocol strip (per-listener opt-in),
/// then the H1/h2c discriminator, then the generic H1/H2 serve paths. Generic
/// over the stream so the UDS listener reuses it verbatim.
async fn handle_conn_bridged<S>(
    mut stream: S,
    mut peer: SocketAddr,
    local: SocketAddr,
    core: CoreHandler,
    shutdown: CancellationToken,
    binding: ListenerBinding,
    peer_unix: bool,
) where
    S: monoio::io::AsyncReadRent
        + monoio::io::AsyncWriteRent
        + monoio::io::Splitable
        + AsRawFd
        + 'static,
    S::OwnedRead: monoio::io::AsyncReadRent + 'static,
    S::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
{
    let state = core.holder.load();
    let header_read_timeout = state.serve_config.header_read_timeout;
    let request_start = std::time::Instant::now();
    // (Tier 2) PROXY protocol on a PLAINTEXT listener: strip the header (fail-closed)
    // and override the peer BEFORE the H1/h2c discriminator reads the first bytes.
    if binding.proxy_protocol {
        if !state
            .server
            .listeners
            .iter()
            .find(|l| l.name == core.listener_name.as_ref())
            .is_some_and(|l| l.proxy_sender_allowed(peer.ip()))
        {
            tracing::debug!(%peer, "proxy_protocol: unauthorized transport peer; closing");
            return;
        }
        let header = monoio::select! {
            header = proxy_protocol::reader::read_and_strip(&mut stream, header_read_timeout) => header,
            _ = shutdown.cancelled() => return,
        };
        match header {
            Ok(Some(h)) => {
                if let Some(src) = h.src {
                    tracing::debug!(real_peer = %src, "proxy_protocol: peer overridden");
                    peer = src;
                } else {
                    tracing::debug!(%peer, "proxy_protocol: peer preserved by LOCAL/UNKNOWN");
                }
            }
            _ => {
                tracing::debug!(%peer, "proxy_protocol: missing/malformed header; closing");
                return;
            }
        }
    }
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
        // (#1034) Nothing has been requested yet; the shutdown signal closes.
        let read = monoio::select! {
            read = read_timeout(&mut stream, remaining, &mut read_scratch) => read,
            _ = shutdown.cancelled() => return,
        };
        match read {
            Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
            _ => return,
        }
    };
    // The serve calls below last for the whole connection; free the sniff buffer first
    // instead of holding it in this future until they return.
    drop(read_scratch);
    if is_h2 {
        let ctx = if peer_unix {
            BridgeCtx::unix(local, Proto::Http2)
        } else {
            BridgeCtx::plain(peer, local, Proto::Http2)
        };
        serve_h2_bridged(stream, acc, ctx, core, shutdown, None).await;
    } else {
        let sendfile_fd = (!peer_unix).then(|| stream.as_raw_fd());
        let ctx = if peer_unix {
            BridgeCtx::unix(local, Proto::Http1)
        } else {
            BridgeCtx::plain(peer, local, Proto::Http1)
        };
        handle_h1_bridged(stream, acc, ctx, core, shutdown, sendfile_fd).await;
    }
}

/// Idle floor for keep-alive and h2 connections: Cloudflare keeps pooled origin connections
/// well past a short `keepAliveTimeout`, so an unpadded idle wait closes them almost at once.
const IDLE_FLOOR: std::time::Duration = std::time::Duration::from_secs(90);

/// (#486) Idle window for a connection whose peer presented a VERIFIED client certificate
/// (in prod only Cloudflare's authenticated-origin-pull cert). Cloudflare never resumes TLS to
/// the origin, so each reconnect is a full TCP + TLS + mTLS handshake before PHP starts; at the
/// 90 s floor our timer closed the connections it would have reused. Set once at startup from
/// `--trusted-proxy-idle-secs`; 0 keeps the normal floor.
static TRUSTED_PROXY_IDLE_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Above this many open connections the certified window falls back to the normal floor, so a
/// connection surge can't pin unbounded idle state.
static TRUSTED_PROXY_IDLE_MAX_CONNS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

pub(crate) fn configure_trusted_proxy_idle(secs: u64, max_conns: u64) {
    // The window becomes a timer deadline; an absurd value would overflow `Instant` (#677).
    const MAX_SECS: u64 = 100 * 365 * 24 * 3600;
    TRUSTED_PROXY_IDLE_SECS.store(secs.min(MAX_SECS), std::sync::atomic::Ordering::Relaxed);
    TRUSTED_PROXY_IDLE_MAX_CONNS.store(max_conns, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn trusted_proxy_idle_secs() -> u64 {
    TRUSTED_PROXY_IDLE_SECS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The idle window for this connection: the configured keep-alive padded to [`IDLE_FLOOR`],
/// raised to the trusted-proxy window for a certified peer while the connection count allows.
fn conn_idle_timeout(state: &ServerState, ctx: &BridgeCtx) -> Option<std::time::Duration> {
    use std::sync::atomic::Ordering;
    let certified = ctx
        .tls
        .as_ref()
        .and_then(|t| t.client_cert.as_ref())
        .is_some_and(|c| c.verified);
    idle_window(
        state.serve_config.keep_alive_timeout,
        certified,
        state.metrics.active_conns.load(Ordering::Relaxed),
        TRUSTED_PROXY_IDLE_SECS.load(Ordering::Relaxed),
        TRUSTED_PROXY_IDLE_MAX_CONNS.load(Ordering::Relaxed),
    )
}

fn idle_window(
    keep_alive: Option<std::time::Duration>,
    certified: bool,
    active_conns: u64,
    trusted_secs: u64,
    trusted_max_conns: u64,
) -> Option<std::time::Duration> {
    let floor = keep_alive.map_or(IDLE_FLOOR, |t| t.max(IDLE_FLOOR));
    if certified && trusted_secs > 0 && active_conns <= trusted_max_conns {
        Some(floor.max(std::time::Duration::from_secs(trusted_secs)))
    } else {
        Some(floor)
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
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S::OwnedRead: monoio::io::AsyncReadRent + 'static,
    S::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
{
    let state = core.holder.load();
    let mut h2_cfg = hj_h2::server::Config::default();
    h2_cfg.conn_idle_timeout = conn_idle_timeout(&state, &ctx);
    h2_cfg.preface_timeout = state.serve_config.header_read_timeout;
    h2_cfg.frame_read_timeout = state.serve_config.header_read_timeout;
    h2_cfg.request_body_timeout = state.serve_config.header_read_timeout;
    h2_cfg.request_body_ceiling = state.serve_config.request_body_ceiling;
    h2_cfg.send_stall_timeout = state.serve_config.header_read_timeout;
    h2_cfg.shutdown_idle_stream_timeout = Some(SHUTDOWN_IDLE_GRACE);
    h2_cfg.header_list_size = state.serve_config.max_req_header_size as u32;
    h2_cfg.max_request_body = state.serve_config.max_req_body_size;
    // (#236 residual) share the server-wide buffered-body cap with H1/H3/LSAPI.
    h2_cfg.body_budget = Some(state.body_budget.clone());
    // (Tier 2) Per-connection egress pacing (h2 streams share one pipe, so the
    // rate is connection-wide here; the per-context override is an H1 refinement).
    h2_cfg.bandwidth_limit = state.serve_config.bandwidth_limit;
    // h2c to an mTLS-gated vhost: refuse a body-carrying request from its head, as the H1
    // transport does, instead of buffering the body the pipeline gate then discards. Only
    // a non-exempt plaintext peer on a server with a gated vhost gets the hook at all.
    if !ctx.is_tls
        && !ctx.peer_unix
        && !state.mtls_required_vhosts.is_empty()
        && !hj_core::is_trusted_internal_peer(ctx.peer.ip())
    {
        let holder = core.holder.clone();
        let listener = core.listener_name.clone();
        let (peer_ip, proto) = (ctx.peer.ip(), ctx.proto);
        h2_cfg.early_reject = Some(hj_h2::server::EarlyReject(Arc::new(
            move |head: &hj_h2::server::RequestHead<'_>| {
                h2c_mtls_redirect(&holder.load_full(), &listener, peer_ip, proto, head)
            },
        )));
    }

    // H2 clones its service captures for every stream.  Keep the connection-local
    // handler behind one Arc so that does not clone every Arc-bearing field in
    // CoreHandler (in particular the live and pinned ServerState generations).
    let core = Arc::new(core);
    let service = move |req: hj_core::Request| {
        let core = core.clone();
        let ctx = ctx.clone();
        #[cfg(feature = "otel")]
        {
            async move { core.dispatch_h2(ctx, req).await }
        }
        #[cfg(not(feature = "otel"))]
        {
            // Keep the ordinary build's fast/bridge state machine directly in
            // the service future.  An extra async dispatch wrapper made every
            // FuturesUnordered node substantially larger on the H2 hot path.
            async move {
                let req = req;
                let mut ctx = ctx;
                let state = core.holder.load_full();
                if let Some(response) = core.fast(&state, &ctx, &req).await {
                    return response;
                }
                ctx.request_generation = Some(RequestGeneration(state));
                core.bridge.dispatch_response(req, ctx).await
            }
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

/// The plaintext mTLS-gate redirect for an h2c request head, as a bodiless response: hj-h2
/// sends it before accepting any DATA. The request the pipeline would see carries
/// `:authority` as its Host header, so the probe does too.
fn h2c_mtls_redirect(
    state: &Arc<ServerState>,
    listener: &str,
    peer_ip: std::net::IpAddr,
    proto: Proto,
    head: &hj_h2::server::RequestHead<'_>,
) -> Option<(http::StatusCode, http::HeaderMap)> {
    let mut probe = http::Request::new(hj_core::empty_incoming());
    *probe.method_mut() = head.method.clone();
    *probe.uri_mut() = head.uri.clone();
    *probe.headers_mut() = head.headers.clone();
    if let Some(authority) = head.authority {
        probe
            .headers_mut()
            .insert(http::header::HOST, authority.clone());
    }
    let response = crate::pipeline::plaintext_mtls_redirect(
        state, listener, peer_ip, proto, &mut probe, true,
    )?;
    let (parts, _) = hj_core::stamp_date(response).into_parts();
    Some((parts.status, parts.headers))
}

/// LiteSpeed `maxKeepAliveReq`: the keep-alive connection closes once it has SERVED `max`
/// requests; `0` and `1` both disable keep-alive (OLS stores `max - 1`, #902). `served` is
/// 1-based (incremented before the check), so `max == N` serves exactly N requests then
/// closes on the Nth response.
fn keepalive_exhausted(served: u32, max: u32) -> bool {
    served >= max.max(1)
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
    sendfile_fd: Option<std::os::fd::RawFd>,
) where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S::OwnedRead: monoio::io::AsyncReadRent + 'static,
    S::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
{
    // Requests served on this keep-alive connection (LiteSpeed maxKeepAliveReq enforcement).
    let mut served: u32 = 0;
    let mut read_scratch: Vec<u8> = Vec::new();
    // (Tier 2) One bucket per CONNECTION — pacing must not reset per response. Rebuilt
    // inside the loop only when a response carries a different rate (context override or
    // a post-reload tuning change).
    let mut throttle =
        hj_http::BandwidthThrottle::new(core.holder.load().serve_config.bandwidth_limit);
    loop {
        // Graceful drain: at a clean request boundary (no buffered bytes = idle
        // keep-alive), wait for either the next request OR the shutdown signal — on
        // shutdown, close the idle connection promptly instead of holding it open.
        // Mid-request reads below are NOT interruptible, so an in-flight request always
        // finishes. (A read cancelled here is harmless: we close immediately, so the
        // non-cancel-safe TLS read buffer is never touched again.)
        if acc.is_empty() {
            // (audit M2) One huge upload used to pin its peak `acc` capacity on this
            // keep-alive connection forever; hand it back at the request boundary.
            if acc.capacity() > INTAKE_RETAIN_CAP {
                acc = Vec::with_capacity(8192);
            }
            // (#303) Same proxy-padding floor the H2 idle window applies: CF's edge
            // keeps idle origin connections well past a 5s keepAliveTimeout, and an
            // unpadded H1 idle wait closes them almost immediately (constant
            // reconnect + TLS-handshake churn). H2 has padded to >=90s for a while.
            let keep_alive_timeout = conn_idle_timeout(&core.holder.load(), &ctx);
            monoio::select! {
                biased;
                res = read_timeout(&mut stream, keep_alive_timeout, &mut read_scratch) => {
                    match res {
                        Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
                        Ok(_) => {
                            core.holder.load().metrics.h1_peer_closes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            core.holder.load().metrics.h1_idle_closes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        Err(_) => return,
                    }
                }
                _ = shutdown.cancelled() => {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
        }
        // Select the request's generation only after idle waiting has received
        // bytes. Compatible SIGHUPs must therefore remain visible to the next
        // request on a persistent H1 connection. This exact Arc is then used
        // for intake limits, the on-core fast path and any bridge dispatch.
        let state = core.holder.load_full();
        // Request-size caps from the LiteSpeed config (maxReqHeaderSize/maxReqBodySize),
        // matching the tokio path — mirror hyper's `max_buf_size` 8 KiB floor for the head.
        let max_head = state.serve_config.max_req_header_size.max(8192);
        let max_body = state.serve_config.max_req_body_size;
        // maxKeepAliveReq: close the connection after N requests (0 and 1 disable keep-alive).
        let max_keepalive = state.serve_config.max_keepalive_requests;
        // Parse a complete request head (drops the borrow before mutating `acc`).
        let request_start = std::time::Instant::now();
        let header_read_timeout = state.serve_config.header_read_timeout;
        let parsed = loop {
            let step: ParsedReq = {
                let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                match request_head_progress(req.parse(&acc), acc.len(), max_head) {
                    RequestHeadProgress::Complete(head_len)
                        if head_has_bare_lf(&acc[..head_len]) =>
                    {
                        ParsedReq::Bad
                    }
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
                    http10,
                } => {
                    break (
                        method,
                        uri,
                        headers,
                        head_len,
                        framing,
                        keep_alive,
                        expect_continue,
                        http10,
                    );
                }
                ParsedReq::Bad => {
                    // (#233) An unparsable head (bad method/target/header token) used to
                    // close the connection with zero response bytes: clients see "empty
                    // reply", Cloudflare retries against the peer, and nothing reaches the
                    // access log because the funnel is never entered. Answer 400 + close
                    // like every sibling refusal path (and hyper/LiteSpeed) instead.
                    write_status_close(&mut stream, 400, "Bad Request", &shutdown).await;
                    return;
                }
                ParsedReq::HeadersTooLarge => {
                    write_status_close(
                        &mut stream,
                        431,
                        "Request Header Fields Too Large",
                        &shutdown,
                    )
                    .await;
                    return;
                }
                ParsedReq::MethodNotAllowed => {
                    write_status_close(&mut stream, 405, "Method Not Allowed", &shutdown).await;
                    return;
                }
                ParsedReq::Partial => {
                    if acc.len() > max_head {
                        write_status_close(
                            &mut stream,
                            431,
                            "Request Header Fields Too Large",
                            &shutdown,
                        )
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
                    // (#1034) A request still arriving when shutdown is signalled has not
                    // been processed; closing it lets the drain finish promptly.
                    let read = monoio::select! {
                        read = read_timeout(&mut stream, remaining, &mut read_scratch) => read,
                        _ = shutdown.cancelled() => return,
                    };
                    match read {
                        Ok(n) if n > 0 => acc.extend_from_slice(&read_scratch[..n]),
                        _ => return,
                    }
                }
            }
        };
        let (
            method,
            mut uri,
            mut headers,
            head_len,
            framing,
            mut keep_alive,
            expect_continue,
            http10,
        ) = parsed;
        // The body gets `connTimeout` from here. Restarting it on every read would let a
        // slow client retain a connection and body-budget lease indefinitely by trickling
        // data, so only BODY_MIN_PROGRESS per window extends it, up to the ceiling (#509,
        // #1035).
        let mut body_deadline = H1BodyDeadline::start(
            header_read_timeout,
            state.serve_config.request_body_ceiling,
            acc.len(),
        );
        // maxKeepAliveReq: once this connection has served the configured number of requests,
        // signal close on this (final) response so the client opens a fresh connection.
        served = served.saturating_add(1);
        if keepalive_exhausted(served, max_keepalive) {
            keep_alive = false;
        }
        // A plaintext request the mTLS gate will refuse is answered from its head:
        // reserving body budget, sending 100 Continue or reading the body first would
        // spend all three on a request that is redirected regardless. The body stays
        // unread, so the connection closes after the redirect.
        let carries_body = match framing {
            BodyFraming::Length(len) => len > 0 && len <= max_body,
            BodyFraming::Chunked => true,
            BodyFraming::Reject => false,
        };
        if carries_body && !ctx.is_tls && !state.mtls_required_vhosts.is_empty() {
            let mut probe = http::Request::new(hj_core::empty_incoming());
            *probe.method_mut() = method.clone();
            *probe.uri_mut() = uri;
            *probe.version_mut() = http::Version::HTTP_11;
            *probe.headers_mut() = headers;
            if http10 {
                probe.extensions_mut().insert(hj_core::Http10Request);
            }
            let refused = crate::pipeline::plaintext_mtls_redirect(
                &state,
                &core.listener_name,
                ctx.peer.ip(),
                ctx.proto,
                &mut probe,
                false,
            );
            let (parts, _) = probe.into_parts();
            uri = parts.uri;
            headers = parts.headers;
            if let Some(response) = refused {
                let response = bridge::fast_response(hj_core::stamp_date(response), false).await;
                let outcome = write_h1_response(
                    &mut stream,
                    response,
                    method == http::Method::HEAD,
                    false,
                    http10,
                    &mut throttle,
                    None,
                    header_read_timeout,
                    &shutdown,
                )
                .await;
                if !outcome.failed {
                    lingering_close(&mut stream, &shutdown).await;
                }
                return;
            }
        }
        // The reservation follows the allocation into dispatch, including body
        // frames retained by a backend writer after the response completes.
        let mut body_lease: Option<hj_core::budget::BodyBufferLease> = None;
        let body_bytes: Vec<u8> = match framing {
            BodyFraming::Reject => {
                write_status_close(&mut stream, 400, "Bad Request", &shutdown).await;
                return;
            }
            BodyFraming::Length(content_length) => {
                // Bound buffered request-body memory: reject an oversized declared length
                // up front (413) instead of reading gigabytes into `acc`.
                if content_length > max_body {
                    write_status_close(&mut stream, 413, "Payload Too Large", &shutdown).await;
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
                        release_refused_body(&mut body_lease, &mut acc);
                        write_status_close(&mut stream, 503, "Service Unavailable", &shutdown)
                            .await;
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
                    match read_before_deadline(
                        &mut stream,
                        body_deadline.as_ref().map(|d| d.deadline),
                        &mut read_scratch,
                    )
                    .await
                    {
                        Ok(n) if n > 0 => {
                            acc.extend_from_slice(&read_scratch[..n]);
                            if let Some(deadline) = body_deadline.as_mut() {
                                deadline.received(acc.len());
                            }
                            // Top the reservation up to the bytes actually buffered.
                            let buffered =
                                (acc.len().saturating_sub(head_len)).min(content_length) as u64;
                            if !ensure_reserved(&mut body_lease, buffered) {
                                tracing::debug!(
                                    %ctx.peer,
                                    "uring h1: body buffer budget exhausted mid-body"
                                );
                                release_refused_body(&mut body_lease, &mut acc);
                                write_status_close(
                                    &mut stream,
                                    503,
                                    "Service Unavailable",
                                    &shutdown,
                                )
                                .await;
                                return;
                            }
                        }
                        _ => return,
                    }
                }
                take_fixed_body(&mut acc, head_len, content_length)
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
                // to pre-declare anything). The DECODED payload lives in `dec.body` while
                // the RAW chunk stream stays buffered in `acc` until the final drain, so
                // both are real heap: charging only the decoded copy let every uploading
                // connection under-count the server-wide ledger by ~1x its body.
                let mut accounted: u64 = 0;
                let end = loop {
                    let step = dec.advance(&acc);
                    let buffered = chunked_accounted_bytes(dec.body.len(), acc.len(), head_len);
                    if buffered > accounted {
                        let ok = body_lease
                            .get_or_insert_with(|| {
                                hj_core::budget::BodyBufferLease::new(state.body_budget.clone())
                            })
                            .reserve(buffered - accounted);
                        if !ok {
                            tracing::debug!(%ctx.peer, "uring h1: body buffer budget exhausted");
                            release_refused_body(&mut body_lease, &mut acc);
                            dec.body = Vec::new();
                            write_status_close(&mut stream, 503, "Service Unavailable", &shutdown)
                                .await;
                            return;
                        }
                        accounted = buffered;
                    }
                    match step {
                        ChunkStep::Done(end) => break end,
                        ChunkStep::Bad if dec.too_large => {
                            release_refused_body(&mut body_lease, &mut acc);
                            dec.body = Vec::new();
                            write_status_close(&mut stream, 413, "Payload Too Large", &shutdown)
                                .await;
                            return;
                        }
                        ChunkStep::Bad => {
                            release_refused_body(&mut body_lease, &mut acc);
                            dec.body = Vec::new();
                            write_status_close(&mut stream, 400, "Bad Request", &shutdown).await;
                            return;
                        }
                        ChunkStep::NeedMore => {
                            match read_before_deadline(
                                &mut stream,
                                body_deadline.as_ref().map(|d| d.deadline),
                                &mut read_scratch,
                            )
                            .await
                            {
                                Ok(n) if n > 0 => {
                                    acc.extend_from_slice(&read_scratch[..n]);
                                    if let Some(deadline) = body_deadline.as_mut() {
                                        deadline.received(acc.len());
                                    }
                                }
                                _ => return,
                            }
                        }
                    }
                };
                let bb = std::mem::take(&mut dec.body);
                acc.drain(..end);
                release_intake_capacity(&mut acc);
                // Right-size the lease: the raw chunk framing drained above was charged
                // alongside the decoded body, but only the decoded copy (`bb`) lives on
                // (any pipelined bytes beyond `end` are re-charged by their own request).
                let excess = accounted.saturating_sub(bb.len() as u64);
                if excess > 0 {
                    if let Some(lease) = body_lease.as_mut() {
                        lease.release(excess);
                    }
                }
                // Transfer-Encoding was stripped; hand the backend an explicit length so
                // CONTENT_LENGTH/$_SERVER and LSAPI framing are correct.
                // classify_framing already rejected TE+CL, so no CL exists to shadow.
                if let Ok(v) = http::HeaderValue::from_str(&bb.len().to_string()) {
                    headers.insert(http::header::CONTENT_LENGTH, v);
                }
                bb
            }
        };

        let decode_tried =
            request_body::finish_body_decodes(&headers, &body_bytes, state.request_decompression);
        let body_bytes = match request_body::finish_body(
            &mut headers,
            body_bytes,
            body_lease,
            &state.body_budget,
            max_body,
            state.request_decompression,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(status) => {
                write_status_close(
                    &mut stream,
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("Bad Request"),
                    &shutdown,
                )
                .await;
                return;
            }
        };
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
        if decode_tried {
            req.extensions_mut().insert(request_body::DecodeTried);
        }
        if http10 {
            req.extensions_mut().insert(hj_core::Http10Request);
            // RFC 9110 §7.8: a server MUST ignore Upgrade in an HTTP/1.0 request, and a
            // 101 would be a 1xx the client must never see (§15.2). Dropping the field
            // keeps the pipeline and any proxied upstream from attempting the switch.
            req.headers_mut().remove(http::header::UPGRADE);
        }
        let mut upgrade_ready = None;
        if !http10 && hj_proxy::is_websocket_upgrade(req.headers()) {
            let (upgrade, ready) = bridge::UringUpgradeRequest::channel();
            req.extensions_mut().insert(upgrade);
            upgrade_ready = Some(ready);
        }
        #[cfg(feature = "otel")]
        let mut trace = core.trace_request(&state, &ctx, &mut req);
        let dispatch = core.dispatch_h1(state, ctx.clone(), req, upgrade_ready.is_some());
        #[cfg(feature = "otel")]
        let response = match &trace {
            Some(trace) => crate::otel::in_context(trace.context(), dispatch).await,
            None => dispatch.await,
        };
        #[cfg(not(feature = "otel"))]
        let response = dispatch.await;
        let Some(resp) = response else {
            return;
        };
        #[cfg(feature = "otel")]
        if let Some(trace) = &trace {
            trace.response_head(resp.status);
        }
        if resp.status == http::StatusCode::SWITCHING_PROTOCOLS {
            let Some(mut ready) = upgrade_ready else {
                write_status_close(&mut stream, 502, "Bad Gateway", &shutdown).await;
                return;
            };
            let Some(upgrade) = ready.recv().await else {
                write_status_close(&mut stream, 502, "Bad Gateway", &shutdown).await;
                return;
            };
            let head = serialize_h1_upgrade_response(resp.status, &resp.headers);
            let (written, _) = stream.write_all(head).await;
            if written.is_err() {
                return;
            }
            #[cfg(feature = "otel")]
            if let Some(trace) = trace.take() {
                trace.finish("upgraded");
            }
            relay_h1_upgrade(stream, std::mem::take(&mut acc), upgrade, &shutdown).await;
            return;
        }
        let is_head = method == http::Method::HEAD;
        // Full → paced 64 KiB slices when a rate is configured, else one vectored
        // head/body write; Stream → head then drained (paced) chunks. A context
        // bandwidthLimit wins over the connection-wide tuning rate.
        let want_rate = resp
            .bw_rate
            .unwrap_or_else(|| core.holder.load().serve_config.bandwidth_limit);
        if throttle.as_ref().is_none_or(|t| t.rate_bps() != want_rate) {
            throttle = hj_http::BandwidthThrottle::new(want_rate);
        }
        // H1's GOAWAY: a response finished during the drain tells the client not to reuse
        // the connection we are about to close.
        if keep_alive && shutdown.is_cancelled() {
            keep_alive = false;
        }
        let outcome = write_h1_response(
            &mut stream,
            resp,
            is_head,
            keep_alive,
            http10,
            &mut throttle,
            sendfile_fd,
            header_read_timeout,
            &shutdown,
        )
        .await;
        #[cfg(feature = "otel")]
        if let Some(trace) = trace.take() {
            trace.finish(if outcome.failed { "error" } else { "complete" });
        }
        if outcome.close {
            // Bytes already pipelined behind this request say more are in flight (#1036).
            if !outcome.failed && !acc.is_empty() {
                lingering_close(&mut stream, &shutdown).await;
            } else {
                let _ = stream.shutdown().await;
            }
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
        /// The request line said HTTP/1.0: no 1xx interim responses and no
        /// Transfer-Encoding may be sent back (RFC 9110 §15.2, RFC 9112 §6.1).
        http10: bool,
    },
    Partial,
    Bad,
    /// CONNECT: refused before dispatch (no tunneling).
    MethodNotAllowed,
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
    if method == http::Method::CONNECT {
        return ParsedReq::MethodNotAllowed;
    }
    let raw_target = req.path.unwrap_or("/");
    // http::Uri silently drops a fragment; h2/h3 reject one, so H1 must too.
    if raw_target.contains('#') {
        return ParsedReq::Bad;
    }
    let Some((uri, target_authority)) = raw_target
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| request_target(&method, raw_target, uri))
    else {
        return ParsedReq::Bad;
    };
    let mut host_value: Option<&[u8]> = None;
    let mut hdr_map = http::HeaderMap::with_capacity(req.headers.len());
    let mut cl_values: Vec<&[u8]> = Vec::new();
    let mut chunked = false;
    let mut te_other = false;
    let mut host_count = 0usize;
    let mut conn_close = req.version == Some(0);
    // RFC 9112 §9.6: once any `close` option is present the connection closes, whatever
    // else the Connection field(s) carry.
    let mut close_option = false;
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
            host_value.get_or_insert(h.value);
        } else if h.name.eq_ignore_ascii_case("connection") {
            // RFC 7230 §6.1: Connection is a comma-separated token list
            // (e.g. `close, Upgrade`). Match each token, not the whole
            // value — a whole-value compare misses `close` in a multi-token
            // header and mis-frames keep-alive.
            for tok in h.value.split(|&b| b == b',') {
                let tok = tok.trim_ascii();
                if tok.eq_ignore_ascii_case(b"close") {
                    close_option = true;
                    conn_close = true;
                } else if tok.eq_ignore_ascii_case(b"keep-alive") && !close_option {
                    conn_close = false;
                }
            }
        }
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(h.name.as_bytes()),
            http::HeaderValue::from_bytes(h.value),
        ) {
            // Identical duplicate CL lines (the only duplicates the framing
            // check accepts) are forwarded as ONE so a lenient upstream cannot
            // re-parse two lines differently; conflicting duplicates are
            // rejected by the framing check regardless of what lands here.
            if n == http::header::CONTENT_LENGTH
                && hdr_map.contains_key(http::header::CONTENT_LENGTH)
            {
                continue;
            }
            hdr_map.append(n, v);
        }
    }
    // One Cookie view for every consumer, as on H2/H3: lsphp builds `$_COOKIE` from a
    // last-wins header slot, while the cache key would parse a joined view (#671).
    hj_core::coalesce_cookie_crumbs(&mut hdr_map);
    // RFC 7230 §3.3.3: reject smuggling-prone framing — both TE and CL present,
    // a non-chunked/compound TE, a non-numeric/overflowing CL, or conflicting
    // duplicate CL values. (A malformed/duplicate CL silently coerced to a length
    // would frame the body short and leak the trailing bytes as the next request.)
    // Decided by `codec::classify_framing` so the served path and the fuzzers agree.
    if let Some(authority) = &target_authority {
        // RFC 9112 §3.2.2: an absolute-form target's authority replaces any Host, so
        // routing, cache keys and backends all see the one authority.
        match http::HeaderValue::from_str(authority) {
            Ok(value) => {
                hdr_map.insert(http::header::HOST, value);
            }
            Err(_) => return ParsedReq::Bad,
        }
    } else {
        match host_value {
            Some(value) => {
                if !std::str::from_utf8(value).is_ok_and(hj_core::valid_http_authority) {
                    return ParsedReq::Bad;
                }
            }
            // RFC 9112 §3.2: an HTTP/1.1 request without Host is malformed.
            None if req.version == Some(1) => return ParsedReq::Bad,
            None => {}
        }
    }
    let framing = if host_count > 1 {
        // RFC 9112 §3.2: a request with multiple Host lines is malformed
        // (MUST reject or replace). Routing, foreign-host protection and
        // cache keys read only the first while hj-proxy forwards BOTH —
        // so reject rather than forward the ambiguity.
        BodyFraming::Reject
    } else if req.version == Some(0) && (chunked || te_other) {
        // RFC 9112 §6.1: Transfer-Encoding in an HTTP/1.0 message means faulty framing
        // (a 1.0 intermediary would not have decoded it), so never decode-and-reuse (#669).
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
        http10: req.version == Some(0),
    }
}

/// RFC 9112 §3.2 request-target forms for an origin server. Returns the origin-form URI
/// and, for absolute-form, the authority that replaces Host. Authority-form (CONNECT
/// only) and asterisk-form outside OPTIONS are refused.
fn request_target(
    method: &http::Method,
    raw: &str,
    uri: http::Uri,
) -> Option<(http::Uri, Option<String>)> {
    if raw == "*" {
        return (method == http::Method::OPTIONS).then_some((uri, None));
    }
    if raw.starts_with('/') {
        return (uri.scheme().is_none() && uri.authority().is_none()).then_some((uri, None));
    }
    let scheme = uri.scheme_str()?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = uri.authority()?.as_str().to_owned();
    if !hj_core::valid_http_authority(&authority) {
        return None;
    }
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let origin = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    Some((origin.parse().ok()?, Some(authority)))
}

// The pure request-framing primitives (`BodyFraming`, `classify_framing`,
// `ChunkedDecoder`, `te_is_chunked`, `resolve_content_length`, `parse_chunk_size`)
// live in `codec.rs` — synchronous and fuzz-reachable via the crate `lib.rs`. Imported above.

/// A refused request's buffered body and its budget reservation are released before the
/// lingering close, which can outlive the refusal by seconds while it discards input.
fn release_refused_body(lease: &mut Option<hj_core::budget::BodyBufferLease>, acc: &mut Vec<u8>) {
    lease.take();
    *acc = Vec::new();
}

/// Write a minimal status line + `Connection: close` and close the connection with a
/// lingering close: these refusals usually leave request bytes unread (#1036).
/// Used to refuse a smuggling-prone / unframable request without dispatching it.
async fn write_status_close<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    shutdown: &CancellationToken,
) where
    S: AsyncReadRent + AsyncWriteRent,
{
    let head =
        format!("HTTP/1.1 {status} {reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    if stream.write_all(head.into_bytes()).await.0.is_err() {
        return;
    }
    lingering_close(stream, shutdown).await;
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
    // RFC 9110 §8.6: a 304/HEAD Content-Length must equal the 200's length, so
    // only a handler-declared length (or a real HEAD body) may be advertised.
    if status == http::StatusCode::NOT_MODIFIED {
        return declared_response_length(headers)
            .map_or(H1ResponseFraming::None, H1ResponseFraming::ContentLength);
    }
    if is_head {
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

/// Status line plus the framing and connection lines an H1 head adds beyond the
/// response's own headers (a 20-digit content-length at most).
const H1_HEAD_FIXED_BYTES: usize = 128;

/// One exactly sized head buffer: growing from a fixed guess reallocated a large header
/// set (1.6 KiB on the forum) through three size classes per response, and under
/// `MIMALLOC_PURGE_DELAY=0` those sparsely used classes re-faulted their pages.
fn h1_head_capacity(headers: &http::HeaderMap) -> usize {
    H1_HEAD_FIXED_BYTES
        + headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum::<usize>()
}

fn serialize_h1_response_head(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    body_len: usize,
    is_head: bool,
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut out: Vec<u8> = Vec::with_capacity(h1_head_capacity(headers));
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
    // An empty buffered HEAD body is the handler dropping the payload, not a
    // zero-length representation.
    let known_len = (!is_head || body_len > 0).then_some(body_len as u64);
    match h1_response_framing(status, headers, known_len, is_head) {
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

async fn relay_h1_upgrade<S>(
    stream: S,
    prefix: Vec<u8>,
    upgrade: bridge::UringUpgradeIo,
    shutdown: &CancellationToken,
) where
    S: monoio::io::AsyncReadRent + monoio::io::AsyncWriteRent + monoio::io::Splitable + 'static,
    S::OwnedRead: monoio::io::AsyncReadRent + 'static,
    S::OwnedWrite: monoio::io::AsyncWriteRent + 'static,
{
    let (mut reader, mut writer) = stream.into_split();
    let bridge::UringUpgradeIo {
        to_upstream,
        mut from_upstream,
    } = upgrade;
    // Each direction returns true on a clean EOF (half-close), false on an error. Like
    // copy_bidirectional, a clean EOF closes the opposite write half (dropping the
    // sender is the upstream-side EOF signal) and the other direction keeps relaying
    // for a bounded drain; an error ends the relay (#805).
    let to_upstream = async move {
        if !prefix.is_empty() && to_upstream.send(bytes::Bytes::from(prefix)).await.is_err() {
            return false;
        }
        let clean = loop {
            let (result, buffer) = reader.read(vec![0u8; 16 * 1024]).await;
            let Ok(read) = result else { break false };
            if read == 0 {
                break true;
            }
            if to_upstream
                .send(bytes::Bytes::copy_from_slice(&buffer[..read]))
                .await
                .is_err()
            {
                break false;
            }
        };
        drop(to_upstream);
        clean
    };
    let from_upstream = async move {
        while let Some(item) = from_upstream.recv().await {
            let Ok(bytes) = item else { return false };
            let (result, _) = writer.write_all(bytes.to_vec()).await;
            if result.is_err() {
                return false;
            }
        }
        writer.shutdown().await.is_ok()
    };
    let mut to_upstream = std::pin::pin!(to_upstream);
    let mut from_upstream = std::pin::pin!(from_upstream);
    // An established relay has no request boundary to stop at, so without the shutdown arm it
    // holds the whole drain grace on every restart — and a client that vanished with no
    // FIN/RST would hold it even after keepalive reaps the socket, because the read has
    // already returned.
    let client_closed_first = monoio::select! {
        clean = &mut to_upstream => {
            if !clean {
                return;
            }
            true
        }
        clean = &mut from_upstream => {
            if !clean {
                return;
            }
            false
        }
        _ = shutdown.cancelled() => return,
    };
    let drain = crate::pipeline::UPGRADE_HALF_CLOSE_DRAIN;
    if client_closed_first {
        monoio::select! {
            _ = monoio::time::timeout(drain, from_upstream) => {}
            _ = shutdown.cancelled() => {}
        }
    } else {
        monoio::select! {
            _ = monoio::time::timeout(drain, to_upstream) => {}
            _ = shutdown.cancelled() => {}
        }
    }
}

/// Write a `BridgeResp` to the H1 wire. `Full` gathers the head and body in one vectored write;
/// `Stream` writes the head then drains chunks. Returns true if the connection must close
/// (write error, no keep-alive, or a mid-stream abort that desynced framing).

/// Serialize an interim `103 Early Hints` response carrying the backend's
/// preload/preconnect `Link` headers, or `None` when there are none. HTTP/1.1
/// parity with hj-h2's h2 emitter.
fn build_103_early_hints(headers: &http::HeaderMap) -> Option<Vec<u8>> {
    let links: Vec<&http::HeaderValue> = headers
        .get_all(http::header::LINK)
        .iter()
        .filter(|v| hj_h2::server::is_early_hint_link(v))
        .collect();
    if links.is_empty() {
        return None;
    }
    let mut interim = String::from("HTTP/1.1 103 Early Hints\r\n");
    for v in links {
        interim.push_str("Link: ");
        interim.push_str(&String::from_utf8_lossy(v.as_bytes()));
        interim.push_str("\r\n");
    }
    interim.push_str("\r\n");
    Some(interim.into_bytes())
}

/// The final response head, preceded by its interim 103 when there is one.
fn with_interim(interim: Option<Vec<u8>>, head: Vec<u8>) -> Vec<u8> {
    match interim {
        Some(mut wire) => {
            wire.extend_from_slice(&head);
            wire
        }
        None => head,
    }
}

#[cfg(test)]
mod idle_window_tests {
    use super::*;
    use std::time::Duration;

    /// Regression (#605): a missing keep-alive timeout still bounds idle connections.
    #[test]
    fn missing_keep_alive_timeout_still_has_the_idle_floor() {
        assert_eq!(idle_window(None, false, 0, 0, u64::MAX), Some(IDLE_FLOOR));
        assert_eq!(
            idle_window(None, true, 0, 300, 6000),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn certified_peers_get_the_trusted_window_until_the_connection_cap() {
        let ka = Some(Duration::from_secs(5));
        // Everyone keeps the 90 s floor by default.
        assert_eq!(idle_window(ka, true, 10, 0, 6000), Some(IDLE_FLOOR));
        // Uncertified peers never get the longer window.
        assert_eq!(idle_window(ka, false, 10, 300, 6000), Some(IDLE_FLOOR));
        assert_eq!(
            idle_window(ka, true, 10, 300, 6000),
            Some(Duration::from_secs(300))
        );
        // A connection surge falls back to the floor.
        assert_eq!(idle_window(ka, true, 6001, 300, 6000), Some(IDLE_FLOOR));
        // A window shorter than the floor never lowers it.
        assert_eq!(idle_window(ka, true, 10, 30, 6000), Some(IDLE_FLOOR));
    }
}

#[cfg(test)]
mod early_hints_tests {
    use super::*;

    #[test]
    fn build_103_includes_only_preload_and_preconnect_links() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::LINK,
            http::HeaderValue::from_static("</a.css>; rel=preload"),
        );
        h.append(
            http::header::LINK,
            http::HeaderValue::from_static("</b.js>; rel=\"preconnect\""),
        );
        h.append(
            http::header::LINK,
            http::HeaderValue::from_static("<https://x/>; rel=canonical"),
        );
        let out = build_103_early_hints(&h).expect("interim response");
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 103 Early Hints\r\n"));
        assert!(text.contains("Link: </a.css>; rel=preload\r\n"));
        assert!(text.contains("preconnect"));
        assert!(!text.contains("canonical"), "non-hint relations stay out");
    }

    #[test]
    fn build_103_is_none_without_hint_links() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::LINK,
            http::HeaderValue::from_static("<https://x/>; rel=canonical"),
        );
        assert!(build_103_early_hints(&h).is_none());
    }

    /// Every write the H1 response writer issued, in order.
    #[derive(Default)]
    struct Writes(Vec<Vec<u8>>);

    impl AsyncWriteRent for Writes {
        async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            // SAFETY: an IoBuf guarantees `bytes_init` initialized bytes at `read_ptr`.
            let bytes = unsafe { std::slice::from_raw_parts(buf.read_ptr(), buf.bytes_init()) };
            self.0.push(bytes.to_vec());
            (Ok(bytes.len()), buf)
        }

        async fn writev<T: monoio::buf::IoVecBuf>(
            &mut self,
            buf: T,
        ) -> monoio::BufResult<usize, T> {
            let mut write = Vec::new();
            for index in 0..buf.read_iovec_len() {
                // SAFETY: an IoVecBuf guarantees `read_iovec_len` valid iovecs over
                // initialized bytes at `read_iovec_ptr`.
                let slice = unsafe {
                    let iov = &*buf.read_iovec_ptr().add(index);
                    std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                };
                write.extend_from_slice(slice);
            }
            let len = write.len();
            self.0.push(write);
            (Ok(len), buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn hinted_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::LINK,
            http::HeaderValue::from_static("</a.css>; rel=preload; as=style"),
        );
        headers
    }

    fn writes_for(body: bridge::BridgeBody, http10: bool) -> Vec<Vec<u8>> {
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: hinted_headers(),
            body,
            bw_rate: None,
        };
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let mut writes = Writes::default();
            let outcome = write_h1_response(
                &mut writes,
                response,
                false,
                true,
                http10,
                &mut None,
                None,
                None,
                &CancellationToken::new(),
            )
            .await;
            assert!(!outcome.failed);
            writes.0
        })
    }

    /// Regression (#975): the 103 goes out in the same write as the final head, and the
    /// byte stream is exactly the interim response followed by the final response.
    #[test]
    fn h1_early_hints_share_the_final_head_write() {
        let interim = build_103_early_hints(&hinted_headers()).unwrap();
        let head =
            serialize_h1_response_head(http::StatusCode::OK, &hinted_headers(), 4, false, true);
        let writes = writes_for(
            bridge::BridgeBody::Full(bytes::Bytes::from_static(b"body")),
            false,
        );
        assert_eq!(writes.len(), 1, "103, head and body leave in one write");
        assert_eq!(writes[0], [&interim[..], &head[..], b"body"].concat());

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Ok(bytes::Bytes::from_static(b"chunk")))
            .unwrap();
        drop(tx);
        let writes = writes_for(bridge::BridgeBody::Stream { rx, len: Some(5) }, false);
        let head = serialize_h1_stream_head(
            http::StatusCode::OK,
            &hinted_headers(),
            Some(5),
            false,
            true,
        );
        assert_eq!(writes[0], [&interim[..], &head[..]].concat());
        assert_eq!(
            writes.concat(),
            [&interim[..], &head[..], b"chunk"].concat()
        );

        let path =
            std::env::temp_dir().join(format!("httpjet-early-hints-{}.bin", std::process::id()));
        std::fs::write(&path, b"file").unwrap();
        let writes = writes_for(
            bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len: 4,
                range: None,
                cached: None,
            }),
            false,
        );
        let _ = std::fs::remove_file(&path);
        let head = serialize_h1_stream_head(
            http::StatusCode::OK,
            &hinted_headers(),
            Some(4),
            false,
            true,
        );
        assert_eq!(writes[0], [&interim[..], &head[..]].concat());
        assert_eq!(writes.concat(), [&interim[..], &head[..], b"file"].concat());
    }

    #[test]
    fn h1_early_hints_are_never_sent_to_http10() {
        let writes = writes_for(
            bridge::BridgeBody::Full(bytes::Bytes::from_static(b"body")),
            true,
        );
        let wire = writes.concat();
        assert!(wire.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(!String::from_utf8_lossy(&wire).contains(" 103 "));
    }
}

/// Bytes an H1 response must deliver per send-progress window while its writes are
/// blocked on the client (~273 B/s at 60 s, the H2/H3 rule). Without it any byte of
/// progress restarted the write timers, so a reader draining a few bytes per interval
/// pinned its connection permit, and the upstream or PHP worker of a streamed body.
const H1_SEND_MIN_PROGRESS: u64 = 16 * 1024;

/// Most bytes one write call may report at once: a userspace-TLS write returns only
/// after flushing every record rustls accepted (its 64 KiB buffer limit), so progress
/// inside that call is invisible until it completes.
const H1_WRITE_PROGRESS_GRAIN: u64 = 64 * 1024;

/// Read buffer for a file body that cannot `sendfile` (a unix-socket peer, or a
/// descriptor/filesystem `sendfile` refuses). One buffer per response, reused per
/// chunk: a slow reader holds at most this much heap.
const H1_FILE_READ_CHUNK: usize = 256 * 1024;

/// One H1 response's send-progress clock, shared by the Full, File and Stream paths.
/// Only time spent blocked writing to the client counts: bandwidth-throttle sleeps and
/// waits on a streaming backend happen between writes, so neither a configured rate
/// nor a slow backend can trip it. `window: None` (`connTimeout` disarmed) never fires.
struct SendProgress {
    window: Option<std::time::Duration>,
    blocked: std::time::Duration,
    progressed: u64,
}

impl SendProgress {
    fn new(window: Option<std::time::Duration>) -> Self {
        Self {
            window,
            blocked: std::time::Duration::ZERO,
            progressed: 0,
        }
    }

    /// How long a write of `len` bytes may stay blocked: the rest of this window, plus
    /// one window for each further [`H1_SEND_MIN_PROGRESS`] the call could report.
    fn budget(&self, len: usize) -> Option<std::time::Duration> {
        let window = self.window?;
        let owed = H1_SEND_MIN_PROGRESS - self.progressed;
        let reportable = (len as u64).min(H1_WRITE_PROGRESS_GRAIN);
        let extra = (reportable.saturating_sub(owed) / H1_SEND_MIN_PROGRESS) as u32;
        Some(window.saturating_sub(self.blocked) + window.saturating_mul(extra))
    }

    /// Account one write attempt that moved `sent` bytes after `blocked` waiting. Each
    /// [`H1_SEND_MIN_PROGRESS`] earns one window back; credit never banks past zero.
    fn record(&mut self, sent: usize, blocked: std::time::Duration) -> io::Result<()> {
        let Some(window) = self.window else {
            return Ok(());
        };
        self.progressed = self.progressed.saturating_add(sent as u64);
        self.blocked = self.blocked.saturating_add(blocked);
        let earned = self.progressed / H1_SEND_MIN_PROGRESS;
        if earned > 0 {
            self.progressed %= H1_SEND_MIN_PROGRESS;
            self.blocked = self
                .blocked
                .saturating_sub(window.saturating_mul(earned.min(u64::from(u32::MAX)) as u32));
        }
        if self.blocked >= window {
            return Err(send_progress_timeout());
        }
        Ok(())
    }

    /// Run one write of `len` bytes under its [`Self::budget`], watched by the core's
    /// [`write_watch`] sweeper rather than a timer of its own. Every write is bounded:
    /// even a small one can block on a client that left earlier responses unread or
    /// shrank its receive window.
    async fn timed<F: std::future::Future>(
        &self,
        len: usize,
        write: F,
    ) -> io::Result<(F::Output, std::time::Duration)> {
        let Some(budget) = self.budget(len) else {
            return Ok((write.await, std::time::Duration::ZERO));
        };
        let started = std::time::Instant::now();
        let mut write = std::pin::pin!(write);
        let mut deadline = write_watch::Deadline::new(started + budget);
        std::future::poll_fn(|cx| {
            if deadline.expired() {
                return std::task::Poll::Ready(Err(send_progress_timeout()));
            }
            match write.as_mut().poll(cx) {
                std::task::Poll::Ready(out) => std::task::Poll::Ready(Ok((out, started.elapsed()))),
                std::task::Poll::Pending => {
                    deadline.arm(cx.waker());
                    std::task::Poll::Pending
                }
            }
        })
        .await
    }

    /// `write_all` under the progress rule; hands the buffer back for reuse.
    async fn write_all<S, B>(&mut self, stream: &mut S, mut buf: B) -> io::Result<B>
    where
        S: AsyncWriteRent,
        B: monoio::buf::IoBuf,
    {
        let len = buf.bytes_init();
        let mut written = 0;
        while written < len {
            let ((result, slice), blocked) = self
                .timed(len - written, stream.write(buf.slice(written..len)))
                .await?;
            buf = slice.into_inner();
            let n = match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
                Err(e) => return Err(e),
            };
            written += n;
            self.record(n, blocked)?;
        }
        Ok(buf)
    }

    /// One vectored `write_all` of `parts` under the progress rule.
    async fn write_vectored<S>(
        &mut self,
        stream: &mut S,
        parts: Vec<bytes::Bytes>,
    ) -> io::Result<()>
    where
        S: AsyncWriteRent,
    {
        let mut buffer = hj_h2::owned_iovec::OwnedIoVec::from_bytes(parts)?;
        while !buffer.is_empty() {
            let ((result, returned), blocked) = self
                .timed(buffer.remaining(), stream.writev(buffer))
                .await?;
            buffer = returned;
            let n = match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
                Err(e) => return Err(e),
            };
            buffer.consume(n)?;
            self.record(n, blocked)?;
        }
        Ok(())
    }
}

fn send_progress_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "response send fell below the minimum progress rate",
    )
}

struct WriteOutcome {
    close: bool,
    #[allow(dead_code)] // observed by optional telemetry
    failed: bool,
}
impl WriteOutcome {
    fn new(failed: bool, keep_alive: bool) -> Self {
        Self {
            close: failed || !keep_alive,
            failed,
        }
    }
}

async fn write_h1_response<S>(
    stream: &mut S,
    mut resp: bridge::BridgeResp,
    is_head: bool,
    keep_alive: bool,
    http10: bool,
    throttle: &mut Option<hj_http::BandwidthThrottle>,
    sendfile_fd: Option<std::os::fd::RawFd>,
    send_window: Option<std::time::Duration>,
    shutdown: &CancellationToken,
) -> WriteOutcome
where
    S: AsyncWriteRent,
{
    let completion = resp.completion.take();
    let mut progress = SendProgress::new(send_window);
    // (Tier 2) 103 Early Hints over HTTP/1.1 — parity with the h2 emitter: the backend's
    // preload/preconnect Link headers go out as an interim response ahead of the final
    // head, in the same write (the final response is already complete). Upgrades (101)
    // never reach here, and an HTTP/1.0 client must never see a 1xx (RFC 9110 §15.2; #608).
    let interim = if http10 {
        None
    } else {
        build_103_early_hints(&resp.headers)
    };
    let outcome = match resp.body {
        bridge::BridgeBody::Full(body) => {
            let head = with_interim(
                interim,
                serialize_h1_response_head(
                    resp.status,
                    &resp.headers,
                    body.len(),
                    is_head,
                    keep_alive,
                ),
            );
            let body_forbidden = hj_core::response_body_forbidden(is_head, resp.status);
            let result = if body_forbidden || body.is_empty() {
                progress.write_all(stream, head).await.map(drop)
            } else if let Some(t) = throttle.as_mut() {
                paced_h1_body(stream, head, body, t, &mut progress).await
            } else {
                progress
                    .write_vectored(stream, vec![bytes::Bytes::from(head), body])
                    .await
            };
            WriteOutcome::new(result.is_err(), keep_alive)
        }
        bridge::BridgeBody::File(file) => {
            let result = write_h1_file(
                stream,
                interim,
                resp.status,
                &resp.headers,
                file,
                is_head,
                keep_alive,
                throttle,
                sendfile_fd,
                &mut progress,
            )
            .await;
            WriteOutcome::new(result.is_err(), keep_alive)
        }
        bridge::BridgeBody::Stream { rx, len } => {
            write_h1_stream(
                stream,
                interim,
                resp.status,
                &resp.headers,
                rx,
                len,
                is_head,
                keep_alive,
                http10,
                throttle,
                &mut progress,
                shutdown,
            )
            .await
        }
    };
    if let Some(completion) = completion {
        completion.finish(if outcome.failed {
            hj_core::ResponseEnd::Error
        } else {
            hj_core::ResponseEnd::Complete
        });
    }
    outcome
}

/// Send a pinned file/range over plain TCP or TLS 1.3 kTLS H1. `sendfile(2)` is attempted in
/// bounded chunks; unsupported descriptor/filesystem combinations fall back at
/// the exact current offset to monoio positional reads, preserving correctness
/// even after a partial zero-copy transfer.
async fn write_h1_file<S>(
    stream: &mut S,
    interim: Option<Vec<u8>>,
    status: http::StatusCode,
    headers: &http::HeaderMap,
    mut body: hj_core::FileBody,
    is_head: bool,
    keep_alive: bool,
    throttle: &mut Option<hj_http::BandwidthThrottle>,
    sendfile_fd: Option<std::os::fd::RawFd>,
    progress: &mut SendProgress,
) -> io::Result<()>
where
    S: AsyncWriteRent,
{
    use monoio::buf::{IoBuf, IoBufMut};
    use std::os::fd::BorrowedFd;

    let (start, len) = body.range.map_or((0, body.len), |(start, end)| {
        (start, end.saturating_sub(start) + 1)
    });
    let head = with_interim(
        interim,
        serialize_h1_stream_head(status, headers, Some(len), is_head, keep_alive),
    );
    progress.write_all(stream, head).await?;
    if hj_core::response_body_forbidden(is_head, status) || len == 0 {
        return Ok(());
    }

    let file = match body.file.take() {
        Some(file) => monoio::fs::File::from_std(file)?,
        None => monoio::fs::File::open(&body.path).await?,
    };
    let mut offset = start;
    let end = start
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file range overflow"))?;
    let mut use_sendfile = sendfile_fd.is_some_and(enable_nonblocking_sendfile);
    const CHUNK: usize = 1024 * 1024;
    // A reader that stops draining (zero-window peer) keeps `sendfile` returning
    // EAGAIN. Retry with an exponential backoff so that cannot busy-poll the pinned
    // worker core; the backoff sleeps are time blocked on the client, so a reader
    // below the minimum progress rate is cut off like any other slow H1 reader.
    const SENDFILE_BACKOFF_MAX_US: u64 = 12_800;
    let mut backoff_us: u64 = 100;
    let mut read_buf: Vec<u8> = Vec::new();

    while offset < end {
        let chunk = if throttle.is_some() { 64 * 1024 } else { CHUNK };
        let want = (end - offset).min(chunk as u64) as usize;
        if use_sendfile {
            let out_fd = sendfile_fd.expect("enabled sendfile has an output fd");
            // SAFETY: the connection owns `out_fd` for this entire response and
            // the file object owns its descriptor until the loop completes.
            let sent = rustix::fs::sendfile(
                unsafe { BorrowedFd::borrow_raw(out_fd) },
                unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) },
                Some(&mut offset),
                want,
            );
            match sent {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "sendfile reached EOF before Content-Length",
                    ));
                }
                Ok(written) => {
                    observe_h1_sendfile(written);
                    backoff_us = 100;
                    progress.record(written, std::time::Duration::ZERO)?;
                    if let Some(bucket) = throttle.as_mut() {
                        let wait = bucket.acquire(written as u64);
                        if wait > 0 {
                            monoio::time::sleep(std::time::Duration::from_micros(wait)).await;
                        }
                    }
                    continue;
                }
                Err(error) if error == rustix::io::Errno::INTR => continue,
                Err(error) if error == rustix::io::Errno::AGAIN => {
                    let started = std::time::Instant::now();
                    monoio::time::sleep(std::time::Duration::from_micros(backoff_us)).await;
                    progress.record(0, started.elapsed())?;
                    backoff_us = (backoff_us.saturating_mul(2)).min(SENDFILE_BACKOFF_MAX_US);
                    continue;
                }
                Err(
                    rustix::io::Errno::INVAL
                    | rustix::io::Errno::NOSYS
                    | rustix::io::Errno::OPNOTSUPP,
                ) => {
                    use_sendfile = false;
                    continue;
                }
                Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error())),
            }
        }

        let want = want.min(H1_FILE_READ_CHUNK);
        if read_buf.capacity() < want {
            read_buf = Vec::with_capacity(want);
        }
        let (read, buffer) = file.read_at(read_buf.slice_mut(0..want), offset).await;
        read_buf = buffer.into_inner();
        let read = read?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file reached EOF before Content-Length",
            ));
        }
        if let Some(bucket) = throttle.as_mut() {
            let wait = bucket.acquire(read as u64);
            if wait > 0 {
                monoio::time::sleep(std::time::Duration::from_micros(wait)).await;
            }
        }
        read_buf = progress
            .write_all(stream, read_buf.slice(..read))
            .await?
            .into_inner();
        offset += read as u64;
    }
    Ok(())
}

#[cfg(test)]
mod send_progress_tests {
    use super::*;
    use std::time::{Duration, Instant};

    const WINDOW: Duration = Duration::from_millis(200);

    #[test]
    fn progress_below_the_floor_fails_at_one_window_and_credit_never_banks() {
        let window = Duration::from_secs(60);
        let mut p = SendProgress::new(Some(window));
        p.record(1000, Duration::from_secs(30)).unwrap();
        assert!(p.record(1000, Duration::from_secs(30)).is_err());

        let mut p = SendProgress::new(Some(window));
        p.record(8 * 1024, Duration::from_secs(50)).unwrap();
        p.record(8 * 1024, Duration::from_secs(5)).unwrap();
        p.record(100, Duration::from_secs(59))
            .expect("16 KiB within the window starts a fresh one");

        let mut p = SendProgress::new(Some(window));
        p.record(1 << 20, Duration::ZERO).unwrap();
        assert!(
            p.record(0, window).is_err(),
            "a fast burst must not bank credit for a later stall"
        );

        let mut p = SendProgress::new(None);
        assert_eq!(p.budget(1 << 20), None);
        p.record(0, Duration::from_secs(1 << 20)).unwrap();
    }

    #[test]
    fn one_write_may_wait_for_the_windows_its_reportable_bytes_earn() {
        let window = Duration::from_secs(60);
        let p = SendProgress::new(Some(window));
        assert_eq!(p.budget(100), Some(window));
        assert_eq!(p.budget(16 * 1024), Some(window));
        assert_eq!(p.budget(64 * 1024), Some(window * 4));
        assert_eq!(
            p.budget(1 << 20),
            Some(window * 4),
            "capped at the TLS grain"
        );

        let mut p = SendProgress::new(Some(window));
        p.record(64 * 1024, window * 7 / 2)
            .expect("64 KiB in 3.5 windows is above 16 KiB per window");
        assert_eq!(p.blocked, Duration::ZERO);
        assert_eq!(p.budget(100), Some(window));
    }

    /// Accepts at most `per_write` bytes per call, after `delay`: a reader that drains
    /// the socket at a fixed slow rate.
    struct Trickle {
        per_write: usize,
        delay: Duration,
        wire: Vec<u8>,
    }

    impl Trickle {
        fn new(per_write: usize, delay: Duration) -> Self {
            Self {
                per_write,
                delay,
                wire: Vec::new(),
            }
        }
    }

    impl AsyncWriteRent for Trickle {
        async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            monoio::time::sleep(self.delay).await;
            let n = buf.bytes_init().min(self.per_write);
            // SAFETY: an IoBuf guarantees `bytes_init` initialized bytes at `read_ptr`,
            // and `n` never exceeds that.
            let bytes = unsafe { std::slice::from_raw_parts(buf.read_ptr(), n) };
            self.wire.extend_from_slice(bytes);
            (Ok(n), buf)
        }

        async fn writev<T: monoio::buf::IoVecBuf>(
            &mut self,
            buf: T,
        ) -> monoio::BufResult<usize, T> {
            monoio::time::sleep(self.delay).await;
            let mut n = 0;
            for index in 0..buf.read_iovec_len() {
                // SAFETY: an IoVecBuf guarantees `read_iovec_len` valid iovecs over
                // initialized bytes at `read_iovec_ptr`.
                let slice = unsafe {
                    let iov = &*buf.read_iovec_ptr().add(index);
                    std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len)
                };
                let take = slice.len().min(self.per_write - n);
                self.wire.extend_from_slice(&slice[..take]);
                n += take;
                if n == self.per_write {
                    break;
                }
            }
            (Ok(n), buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const BODY_LEN: usize = 256 * 1024;

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "httpjet-send-progress-{tag}-{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, vec![b'f'; BODY_LEN]).unwrap();
        path
    }

    /// Every body shape the H1 writer serves, each `BODY_LEN` bytes.
    fn bodies(file: &std::path::Path) -> Vec<(&'static str, bridge::BridgeBody)> {
        let stream = |len: Option<u64>| {
            let (tx, rx) = tokio::sync::mpsc::channel(BODY_LEN / 8192);
            for _ in 0..BODY_LEN / 8192 {
                tx.try_send(Ok(bytes::Bytes::from(vec![b's'; 8192])))
                    .unwrap();
            }
            bridge::BridgeBody::Stream { rx, len }
        };
        vec![
            (
                "full",
                bridge::BridgeBody::Full(bytes::Bytes::from(vec![b'b'; BODY_LEN])),
            ),
            ("stream", stream(Some(BODY_LEN as u64))),
            ("chunked", stream(None)),
            (
                "file",
                bridge::BridgeBody::File(hj_core::FileBody {
                    path: file.to_path_buf(),
                    file: Some(std::fs::File::open(file).unwrap()),
                    len: BODY_LEN as u64,
                    range: None,
                    cached: None,
                }),
            ),
        ]
    }

    /// Write one response through `writer` under `WINDOW`, bounded by a deadline long
    /// enough for any correct outcome. Returns (failed, elapsed, writer).
    fn send<W: AsyncWriteRent>(
        mut writer: W,
        body: bridge::BridgeBody,
        throttle: Option<hj_http::BandwidthThrottle>,
    ) -> (bool, Duration, W) {
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body,
            bw_rate: None,
        };
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let mut throttle = throttle;
            let started = Instant::now();
            let outcome = monoio::time::timeout(
                Duration::from_secs(5),
                write_h1_response(
                    &mut writer,
                    response,
                    false,
                    true,
                    false,
                    &mut throttle,
                    None,
                    Some(WINDOW),
                    &CancellationToken::new(),
                ),
            )
            .await
            .expect("the response must finish or fail, never hang");
            (outcome.failed, started.elapsed(), writer)
        })
    }

    #[test]
    fn a_reader_below_the_minimum_rate_is_cut_off_for_every_body_shape() {
        let file = temp_file("slow");
        for (shape, body) in bodies(&file) {
            // ~5 KiB per 200 ms window, a third of the floor (and slower under load).
            let (failed, elapsed, writer) =
                send(Trickle::new(256, Duration::from_millis(10)), body, None);
            assert!(failed, "{shape}: a trickling reader must fail the response");
            assert!(
                elapsed < Duration::from_secs(2),
                "{shape}: cut off after one window, not after the whole body ({elapsed:?})"
            );
            assert!(writer.wire.len() < BODY_LEN, "{shape}");
        }
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn a_reader_above_the_minimum_rate_receives_every_body_shape() {
        let file = temp_file("fast");
        for (shape, body) in bodies(&file) {
            // ~160 KiB per 200 ms window: ten times the floor.
            let (failed, _, writer) =
                send(Trickle::new(8192, Duration::from_millis(10)), body, None);
            assert!(!failed, "{shape}: a reader above the floor must be served");
            assert!(writer.wire.len() >= BODY_LEN, "{shape}");
        }
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn throttle_sleeps_and_backend_waits_do_not_count_against_the_window() {
        // Pacing 768 KiB at 512 KiB/s sleeps ~1 s, five windows, with an instant reader.
        let body = bridge::BridgeBody::Full(bytes::Bytes::from(vec![b'p'; 768 * 1024]));
        let (failed, elapsed, _) = send(
            Trickle::new(usize::MAX, Duration::ZERO),
            body,
            hj_http::BandwidthThrottle::new(512 * 1024),
        );
        assert!(
            !failed,
            "a configured bandwidth limit must not trip the rule"
        );
        assert!(
            elapsed >= WINDOW * 2,
            "the throttle really paced ({elapsed:?})"
        );

        // A backend that pauses longer than the window between chunks.
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let producer = std::thread::spawn(move || {
            for _ in 0..3 {
                std::thread::sleep(WINDOW + Duration::from_millis(100));
                tx.blocking_send(Ok(bytes::Bytes::from_static(b"event")))
                    .unwrap();
            }
        });
        let (failed, _, writer) = send(
            Trickle::new(usize::MAX, Duration::ZERO),
            bridge::BridgeBody::Stream { rx, len: None },
            None,
        );
        producer.join().unwrap();
        assert!(!failed, "a slow backend must not trip the client rule");
        assert!(writer.wire.ends_with(b"0\r\n\r\n"));
    }

    /// Records each write call's length.
    #[derive(Default)]
    struct WriteSizes(Vec<usize>);

    impl AsyncWriteRent for WriteSizes {
        async fn write<T: monoio::buf::IoBuf>(&mut self, buf: T) -> monoio::BufResult<usize, T> {
            let n = buf.bytes_init();
            self.0.push(n);
            (Ok(n), buf)
        }

        async fn writev<T: monoio::buf::IoVecBuf>(
            &mut self,
            buf: T,
        ) -> monoio::BufResult<usize, T> {
            let n = (0..buf.read_iovec_len())
                // SAFETY: an IoVecBuf guarantees `read_iovec_len` valid iovecs.
                .map(|index| unsafe { (*buf.read_iovec_ptr().add(index)).iov_len })
                .sum();
            self.0.push(n);
            (Ok(n), buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn file_fallback_reads_into_one_bounded_buffer() {
        let path = std::env::temp_dir().join(format!(
            "httpjet-send-progress-fallback-{}.bin",
            std::process::id()
        ));
        let len = 3 * H1_FILE_READ_CHUNK + 123;
        std::fs::write(&path, vec![b'x'; len]).unwrap();
        let body = bridge::BridgeBody::File(hj_core::FileBody {
            path: path.clone(),
            file: Some(std::fs::File::open(&path).unwrap()),
            len: len as u64,
            range: None,
            cached: None,
        });
        let (failed, _, writes) = send(WriteSizes::default(), body, None);
        let _ = std::fs::remove_file(path);
        assert!(!failed);
        let body_writes = &writes.0[1..];
        assert_eq!(body_writes.iter().sum::<usize>(), len);
        assert!(
            body_writes.iter().all(|&n| n <= H1_FILE_READ_CHUNK),
            "no fallback chunk may exceed the bounded read buffer: {body_writes:?}"
        );
    }

    /// A small complete response is bounded too: a client that reads nothing and
    /// shrinks its receive window can leave even a 60 KiB write unable to finish
    /// (fb8bdd8 wrote these with no deadline at all).
    #[test]
    fn a_small_response_to_a_reader_that_never_reads_fails_after_its_windows() {
        use socket2::{Domain, Socket, Type};

        let response = |len: usize| bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Full(bytes::Bytes::from(vec![b'x'; len])),
            bw_rate: None,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        socket2::SockRef::from(&listener)
            .set_send_buffer_size(4 * 1024)
            .unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let client = std::thread::spawn(move || {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            socket.set_recv_buffer_size(4 * 1024).unwrap();
            socket.connect(&address.into()).unwrap();
            // Read nothing; hold the connection open until the server gives up.
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
            drop(socket);
        });
        let mut runtime = build_core_runtime().unwrap();
        let (failed, elapsed) = runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            let started = Instant::now();
            let outcome = monoio::time::timeout(
                Duration::from_secs(5),
                write_h1_response(
                    &mut socket,
                    response(60 * 1024),
                    false,
                    true,
                    false,
                    &mut None,
                    None,
                    Some(WINDOW),
                    &CancellationToken::new(),
                ),
            )
            .await
            .expect("a small response must not wait on a client that never reads");
            (outcome.failed, started.elapsed())
        });
        let _ = done_tx.send(());
        client.join().unwrap();
        assert!(failed, "a reader that never reads must fail the response");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn sendfile_to_a_stalled_reader_fails_after_one_window() {
        use std::io::Read;

        let path = std::env::temp_dir().join(format!(
            "httpjet-send-progress-sendfile-{}.bin",
            std::process::id()
        ));
        let len = 64 * 1024 * 1024;
        std::fs::File::create(&path)
            .unwrap()
            .set_len(len as u64)
            .unwrap();
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len,
                range: None,
                cached: None,
            }),
            bw_rate: None,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // Accepted sockets inherit the small send buffer, so the reader stalls quickly.
        socket2::SockRef::from(&listener)
            .set_send_buffer_size(16 * 1024)
            .unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let client = std::thread::spawn(move || {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            socket.set_recv_buffer_size(16 * 1024).unwrap();
            socket.connect(&address.into()).unwrap();
            let mut socket: std::net::TcpStream = socket.into();
            let mut byte = [0u8; 1];
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            // Stop reading but hold the connection open until the server gives up.
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
        });
        let mut runtime = build_core_runtime().unwrap();
        let (failed, elapsed) = runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            let fd = socket.as_raw_fd();
            let started = Instant::now();
            let outcome = monoio::time::timeout(
                Duration::from_secs(5),
                write_h1_response(
                    &mut socket,
                    response,
                    false,
                    false,
                    false,
                    &mut None,
                    Some(fd),
                    Some(WINDOW),
                    &CancellationToken::new(),
                ),
            )
            .await
            .expect("a stalled sendfile must fail within the window, not the old 60 s");
            (outcome.failed, started.elapsed())
        });
        let _ = done_tx.send(());
        client.join().unwrap();
        let _ = std::fs::remove_file(path);
        assert!(failed, "a stalled reader must fail the file response");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    }
}

#[cfg(test)]
static H1_SENDFILE_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
fn observe_h1_sendfile(written: usize) {
    #[cfg(test)]
    H1_SENDFILE_BYTES.fetch_add(written as u64, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(test))]
    let _ = written;
}

/// `sendfile(2)` itself is synchronous. Monoio may own a blocking socket fd,
/// which would pin the entire thread-per-core worker when a client stops
/// reading. Switch the shared file description to nonblocking before the first
/// call; monoio's socket operations and the direct-write wrapper already
/// support this mode.
fn enable_nonblocking_sendfile(fd: std::os::fd::RawFd) -> bool {
    // SAFETY: `fd` is the live connection descriptor and both fcntl operations
    // only inspect/update its status flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        flags >= 0
            && (flags & libc::O_NONBLOCK != 0
                || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0)
    }
}

/// (Tier 2) Throttled full-body write: the head goes out immediately, then the body in
/// 64 KiB slices, each gated by the token bucket (acquire → sleep the returned µs).
async fn paced_h1_body<S>(
    stream: &mut S,
    head: Vec<u8>,
    body: bytes::Bytes,
    throttle: &mut hj_http::BandwidthThrottle,
    progress: &mut SendProgress,
) -> io::Result<()>
where
    S: AsyncWriteRent,
{
    progress.write_all(stream, head).await?;
    const SLICE: usize = 64 * 1024;
    let mut off = 0usize;
    while off < body.len() {
        let end = (off + SLICE).min(body.len());
        let chunk = body.slice(off..end);
        let wait = throttle.acquire(chunk.len() as u64);
        if wait > 0 {
            monoio::time::sleep(std::time::Duration::from_micros(wait)).await;
        }
        progress.write_all(stream, chunk).await?;
        off = end;
    }
    Ok(())
}

/// Write a streamed H1 response: head, then drain the chunk channel. `len: Some(n)` ⇒
/// `content-length: n` + raw bytes (resumable downloads); `None` ⇒ `transfer-encoding:
/// chunked`. `HEAD` and body-forbidden statuses write only the head. An `Err(())` from the
/// channel is a mid-stream upstream abort AFTER the head was sent — we can no longer 502, so
/// close the connection (a partial body under CL, or an unterminated chunked stream, would
/// desync the next pipelined request).
async fn write_h1_stream<S>(
    stream: &mut S,
    interim: Option<Vec<u8>>,
    status: http::StatusCode,
    headers: &http::HeaderMap,
    mut rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ()>>,
    len: Option<u64>,
    is_head: bool,
    keep_alive: bool,
    http10: bool,
    throttle: &mut Option<hj_http::BandwidthThrottle>,
    progress: &mut SendProgress,
    shutdown: &CancellationToken,
) -> WriteOutcome
where
    S: AsyncWriteRent,
{
    // An HTTP/1.0 recipient cannot decode chunked framing (RFC 9112 §6.1): an
    // unknown-length body is delimited by closing the connection instead (#609).
    let close_delimited =
        http10 && h1_response_framing(status, headers, len, is_head) == H1ResponseFraming::Chunked;
    let keep_alive = keep_alive && !close_delimited;
    let head = if close_delimited {
        serialize_h1_head_framed(status, headers, H1ResponseFraming::None, false)
    } else {
        serialize_h1_stream_head(status, headers, len, is_head, keep_alive)
    };
    if progress
        .write_all(stream, with_interim(interim, head))
        .await
        .is_err()
    {
        return WriteOutcome::new(true, keep_alive);
    }
    if hj_core::response_body_forbidden(is_head, status) {
        rx.close();
        return WriteOutcome::new(false, keep_alive);
    }
    let chunked = len.is_none() && !close_delimited;
    let mut stopping = false;
    loop {
        let item = match next_stream_chunk(&mut rx, shutdown, &mut stopping).await {
            Ok(Some(item)) => item,
            Ok(None) => break,
            // Idle on its backend through the shutdown grace: closing short of the
            // terminator (or of Content-Length) is H1's truncation signal (#1034).
            Err(()) => return WriteOutcome::new(true, keep_alive),
        };
        match item {
            Ok(b) => {
                if b.is_empty() {
                    continue;
                }
                if let Some(t) = throttle.as_mut() {
                    let wait = t.acquire(b.len() as u64);
                    if wait > 0 {
                        monoio::time::sleep(std::time::Duration::from_micros(wait)).await;
                    }
                }
                let result = if chunked {
                    let mut prefix = Vec::with_capacity(20);
                    push_u64_hex(&mut prefix, b.len() as u64);
                    prefix.extend_from_slice(b"\r\n");
                    progress
                        .write_vectored(
                            stream,
                            vec![
                                bytes::Bytes::from(prefix),
                                b,
                                bytes::Bytes::from_static(b"\r\n"),
                            ],
                        )
                        .await
                } else {
                    progress.write_all(stream, b).await.map(drop)
                };
                if result.is_err() {
                    return WriteOutcome::new(true, keep_alive);
                }
            }
            Err(()) => return WriteOutcome::new(true, keep_alive), // upstream abort
        }
    }
    if chunked
        && progress
            .write_all(stream, bytes::Bytes::from_static(b"0\r\n\r\n"))
            .await
            .is_err()
    {
        return WriteOutcome::new(true, keep_alive);
    }
    WriteOutcome::new(false, keep_alive)
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
    serialize_h1_head_framed(
        status,
        headers,
        h1_response_framing(status, headers, len, is_head),
        keep_alive,
    )
}

fn serialize_h1_head_framed(
    status: http::StatusCode,
    headers: &http::HeaderMap,
    framing: H1ResponseFraming,
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut out: Vec<u8> = Vec::with_capacity(h1_head_capacity(headers));
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
    match framing {
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

/// How long sent data may stay unacknowledged before the kernel aborts the connection:
/// the configured `connTimeout`, the same bound as the other per-connection deadlines.
fn tcp_user_timeout(state: &crate::state::ServerState) -> std::time::Duration {
    state
        .serve_config
        .header_read_timeout
        .unwrap_or(std::time::Duration::from_secs(60))
}

/// Build a `SO_REUSEPORT` TCP listener (std) for a monoio runtime to adopt via
/// [`TcpListener::from_std`]. One independent socket is created PER worker so the
/// kernel load-balances accepts across the per-core runtimes.
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

/// (#1035) The H1 request-body deadline: `connTimeout` from the parsed head, extended
/// by [`hj_core::body_deadline::BodyProgress`] as the body arrives.
struct H1BodyDeadline {
    deadline: std::time::Instant,
    timeout: std::time::Duration,
    progress: hj_core::body_deadline::BodyProgress<std::time::Instant>,
}

impl H1BodyDeadline {
    /// `buffered` is the connection buffer's length (head included) when the body starts.
    fn start(
        timeout: Option<std::time::Duration>,
        ceiling: std::time::Duration,
        buffered: usize,
    ) -> Option<Self> {
        let timeout = timeout?;
        let start = std::time::Instant::now();
        Some(Self {
            deadline: start + timeout,
            timeout,
            progress: hj_core::body_deadline::BodyProgress::new(start, ceiling, buffered as u64),
        })
    }

    /// The connection buffer grew to `buffered` bytes.
    fn received(&mut self, buffered: usize) {
        self.progress.extend(
            &mut self.deadline,
            buffered as u64,
            self.timeout,
            std::time::Instant::now,
        );
    }
}

/// Read under an absolute request deadline. Each successful partial read sees
/// only the deadline's remainder; a read never resets the timer itself.
async fn read_before_deadline<S>(
    stream: &mut S,
    deadline: Option<std::time::Instant>,
    scratch: &mut Vec<u8>,
) -> io::Result<usize>
where
    S: monoio::io::AsyncReadRent,
{
    let timeout =
        deadline.map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()));
    if timeout.is_some_and(|remaining| remaining.is_zero()) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request body deadline exceeded",
        ));
    }
    read_timeout(stream, timeout, scratch).await
}

#[cfg(test)]
mod chunked_tests {
    use super::codec::*;
    use super::*;

    #[test]
    fn h1_request_body_reads_share_one_absolute_deadline() {
        use std::io::Write;

        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            for byte in b"abc" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                stream.flush().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(70));
            }
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(120);
            let mut scratch = Vec::with_capacity(8);
            assert_eq!(
                read_before_deadline(&mut stream, Some(deadline), &mut scratch)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                read_before_deadline(&mut stream, Some(deadline), &mut scratch)
                    .await
                    .unwrap(),
                1
            );
            let error = read_before_deadline(&mut stream, Some(deadline), &mut scratch)
                .await
                .expect_err("third trickled byte must not receive a fresh timeout");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        });
        client.join().unwrap();
    }

    #[test]
    fn multishot_cancel_observes_terminal_and_cannot_touch_reused_slot() {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let inherited = socket.try_clone().unwrap();
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(socket).unwrap();
            let mut old = listener.accept_multi().unwrap();
            let client = std::thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
            let accepted = old.next().await.unwrap().unwrap();
            old.cancel();
            monoio::time::timeout(std::time::Duration::from_secs(2), async {
                while let Some(completion) = old.next().await {
                    match completion {
                        Ok(connection) => drop(connection),
                        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ECANCELED)),
                    }
                }
            })
            .await
            .expect("kernel must acknowledge multishot cancellation");
            // A fresh op can reuse the terminal operation's slab slot. All old
            // stream methods must remain inert rather than detach/cancel it.
            let successor = TcpListener::from_std(inherited).unwrap();
            let mut replacement = successor.accept_multi().unwrap();
            assert!(old.next().await.is_none());
            old.cancel();
            drop(old);
            drop(listener);
            let next = std::thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
            let connection =
                monoio::time::timeout(std::time::Duration::from_secs(2), replacement.next())
                    .await
                    .expect("old stream must not cancel replacement")
                    .unwrap()
                    .unwrap();
            drop(connection);
            drop(accepted);
            drop(client.join().unwrap());
            drop(next.join().unwrap());
        });
    }

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
                use std::os::fd::AsRawFd;
                let flags = unsafe { libc::fcntl(conn.as_raw_fd(), libc::F_GETFD) };
                assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
                assert_ne!(
                    flags & libc::FD_CLOEXEC,
                    0,
                    "multishot accepted fd must be close-on-exec"
                );
                let peer = conn.peer_addr().expect("getpeername");
                assert!(peer.ip().is_loopback());
            }
            drop(accepts);
            // The listener still works single-shot after the stream detaches.
            let extra = std::thread::spawn(move || std::net::TcpStream::connect(addr).unwrap());
            let (conn, peer) = listener.accept().await.expect("single-shot after detach");
            use std::os::fd::AsRawFd;
            let flags = unsafe { libc::fcntl(conn.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "single-shot accepted fd must be close-on-exec"
            );
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
        websocket_test_core_with(1)
    }

    /// One event, then nothing ever again: an SSE stream between events.
    struct EndlessBody(Option<bytes::Bytes>);

    impl http_body::Body for EndlessBody {
        type Data = bytes::Bytes;
        type Error = hj_core::BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
            match self.0.take() {
                Some(event) => std::task::Poll::Ready(Some(Ok(http_body::Frame::data(event)))),
                None => std::task::Poll::Pending,
            }
        }
    }

    struct ChannelBody(tokio::sync::mpsc::Receiver<bytes::Bytes>);

    impl http_body::Body for ChannelBody {
        type Data = bytes::Bytes;
        type Error = hj_core::BoxError;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
            self.0
                .poll_recv(cx)
                .map(|event| event.map(|data| Ok(http_body::Frame::data(data))))
        }
    }

    /// `/trickle`: each gap is well under [`SHUTDOWN_IDLE_GRACE`], the whole stream well
    /// over it, so a drain must let it finish.
    const TRICKLE_EVENTS: [&[u8]; 4] = [
        b"data: a\n\n",
        b"data: b\n\n",
        b"data: c\n\n",
        b"data: d\n\n",
    ];
    const TRICKLE_GAP: std::time::Duration = std::time::Duration::from_millis(700);

    fn event_stream(
        body: impl http_body::Body<Data = bytes::Bytes, Error = hj_core::BoxError>
        + Send
        + Sync
        + 'static,
    ) -> hj_core::Response {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/event-stream")
            .body(hj_core::Body::Stream(http_body_util::BodyExt::boxed(body)))
            .unwrap()
    }

    fn websocket_test_core_with(max_keep_alive_req: u32) -> (tokio::runtime::Runtime, CoreHandler) {
        websocket_test_core_config(|config| config.tuning.max_keep_alive_req = max_keep_alive_req)
    }

    fn websocket_test_core_config(
        tweak: impl FnOnce(&mut hj_core::config::ServerConfig) + Send,
    ) -> (tokio::runtime::Runtime, CoreHandler) {
        websocket_test_core_serve(tweak, |_| {})
    }

    fn websocket_test_core_serve(
        tweak: impl FnOnce(&mut hj_core::config::ServerConfig) + Send,
        serve: impl FnOnce(&mut hj_http::ServeConfig),
    ) -> (tokio::runtime::Runtime, CoreHandler) {
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
            tweak(&mut config);
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
            .unwrap()
        });
        let mut state = state;
        serve(&mut Arc::get_mut(&mut state).unwrap().serve_config);
        let bridge = bridge::spawn_bridge(1, |mut req: hj_core::Request, _ctx| async move {
            if req.uri().path() == "/upload-len" {
                use http_body_util::BodyExt;

                let body = req.into_body().collect().await.unwrap().to_bytes();
                return hj_core::text_response(http::StatusCode::OK, body.len().to_string());
            }

            if req.uri().path() == "/body" {
                use http_body_util::BodyExt;

                let body = req
                    .into_body()
                    .collect()
                    .await
                    .expect("collect test request body")
                    .to_bytes();
                let valid = body.len() == 64 * 1024 && body.iter().all(|byte| *byte == b'x');
                return hj_core::text_response(
                    if valid {
                        http::StatusCode::OK
                    } else {
                        http::StatusCode::BAD_REQUEST
                    },
                    body.len().to_string(),
                );
            }

            if req.uri().path() == "/sse" {
                // An event stream is relayed with no length, whatever its source.
                let events =
                    http_body_util::Full::new(bytes::Bytes::from_static(b"data: 1\n\ndata: 2\n\n"));
                return http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/event-stream")
                    .body(hj_core::Body::Stream(http_body_util::BodyExt::boxed(
                        http_body_util::BodyExt::map_err(events, |never| match never {}),
                    )))
                    .unwrap();
            }

            if req.uri().path() == "/sees-upgrade" {
                let seen = req.headers().contains_key(http::header::UPGRADE)
                    || req
                        .extensions()
                        .get::<bridge::UringUpgradeRequest>()
                        .is_some();
                return hj_core::text_response(
                    http::StatusCode::OK,
                    if seen { "upgrade=yes" } else { "upgrade=no" },
                );
            }

            if req.uri().path() == "/hint" {
                return http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header(http::header::LINK, "</a.css>; rel=preload; as=style")
                    .body(hj_core::Body::Full(bytes::Bytes::from_static(b"hinted")))
                    .unwrap();
            }

            if req.uri().path() == "/slow" {
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                return hj_core::text_response(http::StatusCode::OK, "slow-done");
            }

            if req.uri().path() == "/endless" {
                return event_stream(EndlessBody(Some(bytes::Bytes::from_static(b"data: 1\n\n"))));
            }

            if req.uri().path() == "/trickle" {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tokio::spawn(async move {
                    for event in TRICKLE_EVENTS {
                        tokio::time::sleep(TRICKLE_GAP).await;
                        if tx.send(bytes::Bytes::from_static(event)).await.is_err() {
                            return;
                        }
                    }
                });
                return event_stream(ChannelBody(rx));
            }

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
            let (to_upstream, mut inbound) = tokio::sync::mpsc::channel::<bytes::Bytes>(8);
            let (outbound, from_upstream) = tokio::sync::mpsc::channel(8);
            let half_close = req.uri().path() == "/halfclose";
            tokio::spawn(async move {
                if half_close {
                    // Answer only after the client's half-close, like a WebSocket
                    // server's Close reply.
                    let mut seen = Vec::new();
                    while let Some(bytes) = inbound.recv().await {
                        seen.extend_from_slice(&bytes);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let mut reply = b"reply:".to_vec();
                    reply.extend_from_slice(&seen);
                    let _ = outbound.send(Ok(bytes::Bytes::from(reply))).await;
                    return;
                }
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
                holder: ServingView::new(holder),
                listener_name: Arc::from("test"),
            },
        )
    }

    #[cfg(feature = "ktls")]
    fn ktls_file_test_core(
        root: &std::path::Path,
        source: std::path::PathBuf,
        source_len: u64,
        completion: Option<std::sync::mpsc::Sender<hj_core::ResponseEnd>>,
    ) -> (
        tokio::runtime::Runtime,
        CoreHandler,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let state = runtime.block_on(async {
            std::fs::create_dir_all(root.join("logs")).unwrap();
            let mut config = hj_core::config::ServerConfig::default();
            config.server_root = root.to_path_buf();
            config.tuning.max_keep_alive_req = 4;
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
            .unwrap()
        });
        let observed_direct = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_in_handler = observed_direct.clone();
        let bridge = bridge::spawn_bridge(1, move |req: hj_core::Request, ctx| {
            let source = source.clone();
            let completion = completion.clone();
            observed_in_handler.store(ctx.direct_file_egress, std::sync::atomic::Ordering::Relaxed);
            async move {
                if req.uri().path() == "/short" {
                    return http::Response::new(hj_core::Body::Full(bytes::Bytes::from_static(
                        b"short-after-key-update",
                    )));
                }
                let is_range = req.uri().path() == "/range";
                let mut response = http::Response::builder()
                    .status(if is_range {
                        http::StatusCode::PARTIAL_CONTENT
                    } else {
                        http::StatusCode::OK
                    })
                    .body(hj_core::Body::File(hj_core::FileBody {
                        path: source.clone(),
                        file: Some(std::fs::File::open(&source).unwrap()),
                        len: source_len,
                        range: is_range.then_some((117, source_len - 219)),
                        cached: None,
                    }))
                    .unwrap();
                // Keep the transfer live long enough for the client to inject a
                // KeyUpdate while sendfile owns the response write side.
                response
                    .extensions_mut()
                    .insert(crate::pipeline::PerConnBandwidth(2 * 1024 * 1024));
                if let Some(completion) = completion {
                    response
                        .extensions_mut()
                        .insert(hj_core::ResponseCompletion::new(move |end| {
                            let _ = completion.send(end);
                        }));
                }
                response
            }
        })
        .unwrap();
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        (
            runtime,
            CoreHandler {
                bridge,
                holder: ServingView::new(holder),
                listener_name: Arc::from("test"),
            },
            observed_direct,
        )
    }

    #[cfg(feature = "ktls")]
    fn ktls_test_configs(
        root: &std::path::Path,
    ) -> (
        rustls::pki_types::CertificateDer<'static>,
        monoio_rustls::TlsAcceptor,
        Arc<hj_tls::KtlsConfigTemplate>,
    ) {
        hj_tls::install_crypto_provider().unwrap();
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate = signed.cert.der().clone();
        let cert_file = root.join("cert.pem");
        let key_file = root.join("key.pem");
        std::fs::write(&cert_file, signed.cert.pem()).unwrap();
        std::fs::write(&key_file, signed.signing_key.serialize_pem()).unwrap();
        let listener = hj_core::config::Listener {
            name: "test-tls".into(),
            address: "127.0.0.1:0".into(),
            secure: true,
            vhost_map: Vec::new(),
            tls: Some(hj_core::config::ListenerTls {
                key_file,
                cert_file,
                cert_chain: false,
                ca_cert_file: None,
                client_verify: 0,
                verify_depth: 1,
                enable_stapling: false,
                crl_file: None,
            }),
            uds_path: None,
            proxy_protocol: false,
            proxy_protocol_peers: vec![],
        };
        let mut server = hj_core::config::ServerConfig::default();
        server.server_root = root.to_path_buf();
        let bundle =
            hj_tls::PreparedListenerTls::prepare(&server, &listener, false, false, true).unwrap();
        (
            certificate,
            monoio_rustls::TlsAcceptor::from(bundle.tcp),
            Arc::new(bundle.ktls.unwrap()),
        )
    }

    #[cfg(feature = "ktls")]
    fn ktls_test_client(
        address: SocketAddr,
        certificate: rustls::pki_types::CertificateDer<'static>,
    ) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
        ktls_test_client_version(address, certificate, true)
    }

    #[cfg(feature = "ktls")]
    fn ktls_test_client_version(
        address: SocketAddr,
        certificate: rustls::pki_types::CertificateDer<'static>,
        tls13: bool,
    ) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let versions = if tls13 {
            &[&rustls::version::TLS13][..]
        } else {
            &[&rustls::version::TLS12][..]
        };
        let mut config = rustls::ClientConfig::builder_with_protocol_versions(versions)
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        rustls::StreamOwned::new(connection, socket)
    }

    #[cfg(feature = "ktls")]
    fn h1_content_length(head: &[u8]) -> usize {
        String::from_utf8_lossy(head)
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
            })
            .expect("response content-length")
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
        // 0 and 1 disable keep-alive, as in LiteSpeed (#902).
        assert!(keepalive_exhausted(1, 0));
        assert!(keepalive_exhausted(1, 1));
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
        assert!(te_is_chunked(b"\tchunked\t"));
        // Unicode whitespace is not OWS: hyper/LiteSpeed do not frame these as chunked.
        assert!(!te_is_chunked(b"\xc2\xa0chunked"));
        assert!(!te_is_chunked(b"chunked\xe2\x80\x83"));
        assert!(!te_is_chunked(b"\xc2\x85chunked"));
        assert!(!te_is_chunked(b"   "));
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
    fn chunked_body_over_max_body_is_too_large_not_bad() {
        let mut dec = ChunkedDecoder::new(0);
        dec.max_body = 4;
        assert!(matches!(
            dec.advance(b"5\r\nhello\r\n0\r\n\r\n"),
            ChunkStep::Bad
        ));
        assert!(dec.too_large);
        let mut dec = ChunkedDecoder::new(0);
        assert!(matches!(dec.advance(b"zz\r\n"), ChunkStep::Bad));
        assert!(!dec.too_large, "malformed framing stays 400");
        let mut dec = ChunkedDecoder::new(0);
        dec.max_body = 5;
        assert!(matches!(
            dec.advance(b"5\r\nhello\r\n0\r\n\r\n"),
            ChunkStep::Done(_)
        ));
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

    #[test]
    fn undeclared_304_and_empty_head_never_advertise_zero_length() {
        let empty = http::HeaderMap::new();
        for wire in [
            serialize_h1_response_head(http::StatusCode::NOT_MODIFIED, &empty, 0, false, true),
            serialize_h1_response_head(http::StatusCode::NOT_MODIFIED, &empty, 0, true, true),
            serialize_h1_response_head(http::StatusCode::OK, &empty, 0, true, true),
            serialize_h1_stream_head(http::StatusCode::NOT_MODIFIED, &empty, Some(9), false, true),
        ] {
            let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
            assert!(!text.contains("content-length"), "{text}");
            assert!(!text.contains("transfer-encoding"), "{text}");
            assert!(wire.ends_with(b"\r\n\r\n"));
        }
        let get = serialize_h1_response_head(http::StatusCode::OK, &empty, 0, false, true);
        assert!(String::from_utf8_lossy(&get).contains("content-length: 0\r\n"));
    }

    fn capture_h1_response(response: bridge::BridgeResp) -> Vec<u8> {
        capture_h1_response_throttled(response, &mut None)
    }

    fn capture_h1_response_throttled(
        response: bridge::BridgeResp,
        throttle: &mut Option<hj_http::BandwidthThrottle>,
    ) -> Vec<u8> {
        let (wire, failed) = capture_h1_response_options(response, throttle, false, false, false);
        assert!(!failed);
        wire
    }

    fn capture_h1_response_options(
        response: bridge::BridgeResp,
        throttle: &mut Option<hj_http::BandwidthThrottle>,
        is_head: bool,
        use_sendfile: bool,
        http10: bool,
    ) -> (Vec<u8>, bool) {
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
        let failed = runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let sendfile_fd = use_sendfile.then(|| stream.as_raw_fd());
            let result = write_h1_response(
                &mut stream,
                response,
                is_head,
                false,
                http10,
                throttle,
                sendfile_fd,
                None,
                &CancellationToken::new(),
            )
            .await;
            assert!(result.close);
            let _ = stream.shutdown().await;
            result.failed
        });
        (client.join().unwrap(), failed)
    }

    #[test]
    fn plaintext_h1_sendfile_preserves_large_range_and_content_length() {
        use std::sync::atomic::Ordering;

        let sendfile_before = H1_SENDFILE_BYTES.load(Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "httpjet-sendfile-range-{}-{}.bin",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let bytes: Vec<u8> = (0..(2 * 1024 * 1024 + 333))
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&path, &bytes).unwrap();
        let start = 117u64;
        let end = bytes.len() as u64 - 219;
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::PARTIAL_CONTENT,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len: bytes.len() as u64,
                range: Some((start, end)),
                cached: None,
            }),
            bw_rate: None,
        };
        let (wire, failed) = capture_h1_response_options(response, &mut None, false, true, false);
        assert!(!failed);
        let split = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8_lossy(&wire[..split]).to_ascii_lowercase();
        let expected = (end - start + 1) as usize;
        assert!(head.contains(&format!("content-length: {expected}\r\n")));
        assert_eq!(&wire[split..], &bytes[start as usize..=end as usize]);
        assert!(
            H1_SENDFILE_BYTES
                .load(Ordering::Relaxed)
                .saturating_sub(sendfile_before)
                >= expected as u64,
            "the selected range must traverse sendfile"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plaintext_h1_file_short_read_fails_closed_after_partial_body() {
        let path =
            std::env::temp_dir().join(format!("httpjet-sendfile-short-{}.bin", std::process::id()));
        std::fs::write(&path, b"short").unwrap();
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len: 100,
                range: None,
                cached: None,
            }),
            bw_rate: None,
        };
        let (wire, failed) = capture_h1_response_options(response, &mut None, false, true, false);
        assert!(failed, "short source must close the connection as an error");
        assert!(wire.ends_with(b"short"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plaintext_h1_sendfile_client_abort_is_an_error() {
        use std::io::Read;

        let path =
            std::env::temp_dir().join(format!("httpjet-sendfile-abort-{}.bin", std::process::id()));
        let source = std::fs::File::create(&path).unwrap();
        source.set_len(32 * 1024 * 1024).unwrap();
        drop(source);
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len: 32 * 1024 * 1024,
                range: None,
                cached: None,
            }),
            bw_rate: None,
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            drop(socket);
        });
        let mut runtime = build_core_runtime().unwrap();
        let failed = runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            let fd = socket.as_raw_fd();
            let outcome = write_h1_response(
                &mut socket,
                response,
                false,
                false,
                false,
                &mut None,
                Some(fd),
                None,
                &CancellationToken::new(),
            )
            .await;
            outcome.failed
        });
        client.join().unwrap();
        assert!(
            failed,
            "a peer abort must not complete a partial file response"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plaintext_h1_head_never_sends_file_bytes() {
        let path =
            std::env::temp_dir().join(format!("httpjet-sendfile-head-{}.bin", std::process::id()));
        std::fs::write(&path, b"body-must-not-appear").unwrap();
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::File(hj_core::FileBody {
                path: path.clone(),
                file: Some(std::fs::File::open(&path).unwrap()),
                len: 20,
                range: None,
                cached: None,
            }),
            bw_rate: None,
        };
        let (wire, failed) = capture_h1_response_options(response, &mut None, true, true, false);
        assert!(!failed);
        assert!(wire.ends_with(b"\r\n\r\n"));
        assert!(!wire.windows(4).any(|w| w == b"body"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn throttled_full_body_write_is_paced() {
        // 512 KiB at 300 KiB/s: the initial bucket (1× rate) covers the first burst and
        // the rest drains at the configured rate (~0.7 s). The floor is deliberately
        // generous; the point is "measurably paced", not a precise-duration assertion.
        let body = bytes::Bytes::from(vec![b'x'; 512 * 1024]);
        let tail = body.slice(body.len() - 16..);
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Full(body),
            bw_rate: Some(300_000),
        };
        let started = std::time::Instant::now();
        // The connection loop reconciles resp.bw_rate into the per-connection bucket
        // before calling the writer; mirror that here.
        let mut throttle = hj_http::BandwidthThrottle::new(300_000);
        let wire = capture_h1_response_throttled(response, &mut throttle);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(400),
            "a 512 KiB body at 300 KiB/s must take ≳0.4 s, took {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "pacing ran away: {elapsed:?}"
        );
        assert!(wire.ends_with(&tail[..]), "whole body must be written");
    }

    #[test]
    fn unthrottled_full_body_write_is_not_delayed() {
        let body = bytes::Bytes::from(vec![b'y'; 512 * 1024]);
        let tail = body.slice(body.len() - 16..);
        let response = bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Full(body),
            bw_rate: None,
        };
        let started = std::time::Instant::now();
        let wire = capture_h1_response(response);
        assert!(
            started.elapsed() < std::time::Duration::from_millis(400),
            "no rate configured ⇒ no pacing"
        );
        assert!(wire.ends_with(&tail[..]));
    }

    #[test]
    fn full_and_stream_writers_discard_forbidden_response_bodies() {
        let full = capture_h1_response(bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::NO_CONTENT,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Full(bytes::Bytes::from_static(b"full-sentinel")),
            bw_rate: None,
        });

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Ok(bytes::Bytes::from_static(b"stream-sentinel")))
            .unwrap();
        let streamed = capture_h1_response(bridge::BridgeResp {
            completion: None,
            status: http::StatusCode::NO_CONTENT,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Stream { rx, len: Some(15) },
            bw_rate: None,
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
            completion: None,
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: bridge::BridgeBody::Stream { rx, len: None },
            bw_rate: None,
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

    /// Regression (#609): an HTTP/1.0 client cannot decode chunked framing, so an
    /// unknown-length stream is close-delimited: raw bytes, no Transfer-Encoding.
    #[test]
    fn http10_unknown_length_stream_is_close_delimited() {
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tx.try_send(Ok(bytes::Bytes::from_static(b"chunk-data")))
            .unwrap();
        tx.try_send(Ok(bytes::Bytes::from_static(b"more"))).unwrap();
        drop(tx);
        let (wire, failed) = capture_h1_response_options(
            bridge::BridgeResp {
                completion: None,
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: bridge::BridgeBody::Stream { rx, len: None },
                bw_rate: None,
            },
            &mut None,
            false,
            false,
            true,
        );
        assert!(!failed);
        let split = wire
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let head = String::from_utf8_lossy(&wire[..split]).to_ascii_lowercase();
        assert!(!head.contains("transfer-encoding"), "{head}");
        assert!(!head.contains("content-length"), "{head}");
        assert!(head.contains("connection: close\r\n"), "{head}");
        assert_eq!(&wire[split..], b"chunk-datamore");
    }

    #[test]
    fn http10_known_length_stream_keeps_content_length() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(Ok(bytes::Bytes::from_static(b"abc"))).unwrap();
        drop(tx);
        let (wire, failed) = capture_h1_response_options(
            bridge::BridgeResp {
                completion: None,
                status: http::StatusCode::OK,
                headers: http::HeaderMap::new(),
                body: bridge::BridgeBody::Stream { rx, len: Some(3) },
                bw_rate: None,
            },
            &mut None,
            false,
            false,
            true,
        );
        assert!(!failed);
        let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(text.contains("content-length: 3\r\n"), "{text}");
        assert!(!text.contains("transfer-encoding"), "{text}");
        assert!(text.ends_with("\r\n\r\nabc"), "{text}");
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
                None,
            )
            .await;
        });
        client.join().unwrap();
    }

    /// Regression (#805): after the client half-closes an upgraded connection, the
    /// relay keeps writing upstream data to it until upstream EOF instead of ending at
    /// the first direction to finish.
    #[test]
    fn h1_websocket_relays_upstream_reply_after_client_half_close() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let request =
            String::from_utf8(WS_REQUEST.to_vec())
                .unwrap()
                .replacen("/echo", "/halfclose", 1);
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(local).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let head = read_h1_head(&mut stream);
            assert!(
                String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .starts_with("http/1.1 101 switching protocols\r\n")
            );
            stream.write_all(b"bye").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, b"reply:bye", "upstream reply after the client's FIN");
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
                None,
            )
            .await;
        });
        client.join().unwrap();
    }

    #[test]
    fn extracted_body_capacity_is_released_with_pipelined_bytes_kept() {
        let mut acc = vec![b'x'; 1 << 20];
        acc.push(b'G');
        acc.drain(..1 << 20);
        assert!(acc.capacity() >= 1 << 20, "drain keeps the peak capacity");
        release_intake_capacity(&mut acc);
        assert_eq!(acc, b"G");
        assert!(acc.capacity() <= INTAKE_RETAIN_CAP);
        let mut small = Vec::with_capacity(8192);
        small.extend_from_slice(b"abc");
        let ptr = small.as_ptr();
        release_intake_capacity(&mut small);
        assert_eq!(small.as_ptr(), ptr, "a small buffer is kept as is");
    }

    #[test]
    fn fixed_body_reuses_intake_allocation_and_preserves_pipeline() {
        let head = b"POST /upload HTTP/1.1\r\ncontent-length: 1048576\r\n\r\n";
        let body = vec![b'x'; 1 << 20];
        let pipelined = b"GET /next HTTP/1.1\r\nhost: example.test\r\n\r\n";
        let mut acc = Vec::with_capacity(head.len() + body.len() + pipelined.len());
        acc.extend_from_slice(head);
        acc.extend_from_slice(&body);
        acc.extend_from_slice(pipelined);
        let intake_allocation = acc.as_ptr();

        let extracted = take_fixed_body(&mut acc, head.len(), body.len());

        assert_eq!(extracted, body);
        assert_eq!(acc, pipelined);
        assert_eq!(
            extracted.as_ptr(),
            intake_allocation,
            "the body keeps the intake allocation instead of allocating a second body copy"
        );
    }

    #[test]
    fn empty_fixed_body_keeps_pipeline_without_pinning_intake_allocation() {
        let head = b"GET /first HTTP/1.1\r\nhost: example.test\r\n\r\n";
        let pipelined = b"GET /next HTTP/1.1\r\nhost: example.test\r\n\r\n";
        let mut acc = Vec::with_capacity(1 << 20);
        acc.extend_from_slice(head);
        acc.extend_from_slice(pipelined);
        let oversized_intake = acc.as_ptr();

        let extracted = take_fixed_body(&mut acc, head.len(), 0);

        assert!(extracted.is_empty());
        assert_eq!(extracted.capacity(), 0);
        assert_eq!(acc, pipelined);
        assert!(acc.capacity() <= INTAKE_RETAIN_CAP);
        assert_ne!(
            acc.as_ptr(),
            oversized_intake,
            "the pipeline must not retain the oversized intake allocation"
        );
    }

    #[test]
    fn wildcard_listener_reports_the_accepted_interface_as_local() {
        let std_listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let bound = std_listener.local_addr().unwrap();
        let port = bound.port();
        let client = std::thread::spawn(move || {
            let _s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
        });
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (stream, _peer) = listener.accept().await.unwrap();
            let local = connection_local_addr(&stream, bound);
            assert_eq!(local, SocketAddr::from(([127, 0, 0, 1], port)));
            let fixed: SocketAddr = "192.0.2.1:80".parse().unwrap();
            assert_eq!(connection_local_addr(&stream, fixed), fixed);
        });
        client.join().unwrap();
    }

    /// Server half of [`tls_drain_received_accounts_for_pipelined_records`]: the client
    /// pipelines `sent` plaintext bytes with its Finished; returns (drained, prefix,
    /// plaintext the userspace or raw-socket continuation still yields).
    fn pipelined_after_finished(sent: usize) -> (bool, Vec<u8>, usize) {
        use monoio::io::AsyncReadRent;
        use std::io::Write;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
            .unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        server_config.send_tls13_tickets = 0;
        let acceptor = monoio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let client = std::thread::spawn(move || {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut conn =
                rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                    .unwrap();
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            loop {
                while conn.wants_write() && conn.is_handshaking() {
                    conn.write_tls(&mut socket).unwrap();
                }
                if !conn.is_handshaking() {
                    break;
                }
                conn.read_tls(&mut socket).unwrap();
                conn.process_new_packets().unwrap();
            }
            conn.writer().write_all(&vec![b'A'; sent]).unwrap();
            let mut burst = Vec::new();
            while conn.wants_write() {
                conn.write_tls(&mut burst).unwrap();
            }
            socket.write_all(&burst).unwrap();
            let _ = done_rx.recv_timeout(std::time::Duration::from_secs(10));
        });
        std_listener.set_nonblocking(true).unwrap();
        let mut runtime = build_core_runtime().unwrap();
        let result = runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            monoio::time::sleep(std::time::Duration::from_millis(200)).await;
            let mut prefix = Vec::new();
            let drained = tls.drain_received(&mut prefix).unwrap();
            let mut rest = 0usize;
            if drained {
                // What a kernel-TLS socket would see next: whole records only.
                let (mut io, _session) = tls.into_parts();
                let mut raw = Vec::new();
                while prefix.len() + rest < sent {
                    let (n, buf) = io.read(vec![0u8; 65536]).await;
                    let n = n.unwrap();
                    assert!(n > 0, "socket closed before every record arrived");
                    raw.extend_from_slice(&buf[..n]);
                    let mut at = 0;
                    rest = 0;
                    while at + 5 <= raw.len() {
                        let len = u16::from_be_bytes([raw[at + 3], raw[at + 4]]) as usize;
                        if at + 5 + len > raw.len() {
                            break;
                        }
                        assert_eq!(raw[at], 0x17, "application-data record at offset {at}");
                        rest += len - 17;
                        at += 5 + len;
                    }
                }
            } else {
                while prefix.len() + rest < sent {
                    let (n, _) = tls.read(vec![0u8; 65536]).await;
                    let n = n.unwrap();
                    assert!(n > 0);
                    rest += n;
                }
            }
            (drained, prefix, rest)
        });
        let _ = done_tx.send(());
        client.join().unwrap();
        result
    }

    #[test]
    fn tls_drain_received_accounts_for_pipelined_records() {
        // 5000 bytes sit wholly in the adapter's 16 KiB read-ahead: draining only the
        // decrypted plaintext saw 0 of them, so a kTLS handoff lost all 5000.
        let (drained, prefix, rest) = pipelined_after_finished(5000);
        assert!(drained);
        assert_eq!((prefix.len(), rest), (5000, 0));
        assert!(prefix.iter().all(|&b| b == b'A'));
        // 40000 bytes span the read-ahead: either the remainder is whole records on
        // the socket, or a partial record forces the userspace path; nothing is lost.
        let (_, prefix, rest) = pipelined_after_finished(40000);
        assert_eq!(prefix.len() + rest, 40000);
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
                ClientAuth::None,
                None,
                CancellationToken::new(),
                ListenerBinding::default(),
            )
            .await;
        });
        client.join().unwrap();
    }

    /// clientVerify=1/3 listeners request a client certificate without refusing a
    /// peer that has none: forwarded client identity must then need a presented
    /// one, through the real transport, bridge and pipeline.
    #[test]
    fn optional_client_auth_trusts_forwarded_identity_only_with_a_presented_cert() {
        use std::io::{Read, Write};

        hj_tls::install_crypto_provider().unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (doc_root, state) = runtime
            .block_on(async { crate::pipeline::e2e::forwarded_deny_state("uring-optional-cert") });
        let holder = Arc::new(arc_swap::ArcSwap::from(state));
        let core = runtime.block_on(async {
            CoreHandler {
                bridge: build_pipeline_bridge(
                    ServingView::new(holder.clone()),
                    Arc::from("http"),
                    pipeline_admission(holder.clone()),
                ),
                holder: ServingView::new(holder.clone()),
                listener_name: Arc::from("http"),
            }
        });

        let server = rcgen::generate_simple_self_signed(vec!["canon.test".into()]).unwrap();
        let server_cert = server.cert.der().clone();
        let client = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        let client_cert = client.cert.der().clone();
        let client_key = client.signing_key.serialize_der();
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(client_cert.clone()).unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
                    .allow_unauthenticated()
                    .build()
                    .unwrap(),
            )
            .with_single_cert(
                vec![server_cert.clone()],
                rustls::pki_types::PrivateKeyDer::try_from(server.signing_key.serialize_der())
                    .unwrap(),
            )
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = monoio_rustls::TlsAcceptor::from(Arc::new(server_config));

        // 203.0.113.0/24 is denied; the loopback peer itself is allowed.
        for (present_cert, expected) in [(false, "200"), (true, "403")] {
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let local = std_listener.local_addr().unwrap();
            std_listener.set_nonblocking(true).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(server_cert.clone()).unwrap();
            let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
            let mut client_config = if present_cert {
                builder
                    .with_client_auth_cert(
                        vec![client_cert.clone()],
                        rustls::pki_types::PrivateKeyDer::try_from(client_key.clone()).unwrap(),
                    )
                    .unwrap()
            } else {
                builder.with_no_client_auth()
            };
            client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let client = std::thread::spawn(move || {
                let socket = std::net::TcpStream::connect(local).unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ClientConnection::new(
                    Arc::new(client_config),
                    "canon.test".try_into().unwrap(),
                )
                .unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                stream
                    .write_all(
                        b"GET /page.html HTTP/1.1\r\nHost: canon.test\r\n\
                          CF-Connecting-IP: 203.0.113.9\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                let mut response = Vec::new();
                let _ = stream.read_to_end(&mut response);
                String::from_utf8_lossy(&response).into_owned()
            });
            let core = core.clone();
            let acceptor = acceptor.clone();
            let mut uring = build_core_runtime().unwrap();
            uring.block_on(async move {
                let listener = TcpListener::from_std(std_listener).unwrap();
                let (stream, peer) = listener.accept().await.unwrap();
                handle_tls_bridged(
                    stream,
                    peer,
                    local,
                    core,
                    acceptor,
                    ClientAuth::Optional,
                    None,
                    CancellationToken::new(),
                    ListenerBinding::default(),
                )
                .await;
            });
            let response = client.join().unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "client cert presented={present_cert}: {response}"
            );
        }
        drop(runtime);
        std::fs::remove_dir_all(doc_root).ok();
    }

    #[test]
    fn client_verify_maps_to_requested_and_required_client_auth() {
        for (client_verify, requested, required) in [
            (0, false, false),
            (1, true, false),
            (2, true, true),
            (3, true, false),
        ] {
            let auth = ClientAuth::from_client_verify(client_verify);
            assert_eq!(
                (auth.requested(), auth.required()),
                (requested, required),
                "clientVerify={client_verify}"
            );
        }
    }

    #[test]
    fn h1_tls_preserves_read_ahead_after_coalesced_finished_and_large_post() {
        use std::io::{Read, Write};

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
        let client = std::thread::spawn(move || {
            let mut socket = std::net::TcpStream::connect(local).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned();
            let mut connection = rustls::ClientConnection::new(client_config, name).unwrap();
            connection.set_buffer_limit(Some(128 * 1024));

            let mut request = format!(
                "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                64 * 1024
            )
            .into_bytes();
            request.resize(request.len() + 64 * 1024, b'x');
            // rustls buffers pre-handshake plaintext. Once the server flight is
            // processed, the next write contains the client Finished followed by
            // application records, reproducing a client that pipelines its POST.
            connection.writer().write_all(&request).unwrap();

            let mut initial_flight = Vec::new();
            while connection.wants_write() {
                assert!(connection.write_tls(&mut initial_flight).unwrap() > 0);
            }
            socket.write_all(&initial_flight).unwrap();
            socket.flush().unwrap();

            let mut sent_coalesced_large_flight = false;
            while connection.is_handshaking() {
                let read = connection.read_tls(&mut socket).unwrap();
                assert!(read > 0, "server closed during TLS handshake");
                connection.process_new_packets().unwrap();

                if connection.wants_write() {
                    let mut flight = Vec::new();
                    while connection.wants_write() {
                        assert!(connection.write_tls(&mut flight).unwrap() > 0);
                    }
                    sent_coalesced_large_flight |= flight.len() > 16 * 1024;
                    socket.write_all(&flight).unwrap();
                    socket.flush().unwrap();
                }
            }
            assert!(
                sent_coalesced_large_flight,
                "fixture must coalesce Finished with more than one adapter read of POST data"
            );

            let mut stream = rustls::StreamOwned::new(connection, socket);
            let head = read_h1_head(&mut stream);
            assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
            let mut body = [0u8; 5];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"65536");
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
                ClientAuth::None,
                None,
                CancellationToken::new(),
                ListenerBinding::default(),
            )
            .await;
        });
        client.join().unwrap();
    }

    #[cfg(feature = "ktls")]
    #[test]
    fn ktls_h1_sendfile_preserves_range_across_mid_transfer_key_update() {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;

        let sendfile_before = H1_SENDFILE_BYTES.load(Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "httpjet-ktls-sendfile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("large.bin");
        let bytes: Vec<u8> = (0..(4 * 1024 * 1024 + 333))
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&source, &bytes).unwrap();
        let source_len = bytes.len() as u64;
        let start = 117usize;
        let end = source_len as usize - 219;
        let expected = bytes[start..=end].to_vec();
        let expected_len = expected.len();
        let (tokio_runtime, core, observed_direct) =
            ktls_file_test_core(&root, source, source_len, None);
        let (certificate, acceptor, template) = ktls_test_configs(&root);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = ktls_test_client(local, certificate);
            stream
                .write_all(
                    b"GET /range HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
            let head = read_h1_head(&mut stream);
            let head_text = String::from_utf8_lossy(&head).to_ascii_lowercase();
            assert!(head_text.starts_with("http/1.1 206 partial content\r\n"));
            assert_eq!(h1_content_length(&head), expected.len());
            assert_eq!(
                stream.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );

            let split = 128 * 1024;
            let mut received = vec![0u8; expected.len()];
            stream.read_exact(&mut received[..split]).unwrap();
            assert_eq!(&received[..split], &expected[..split]);

            // Queue UpdateRequested plus the next pipelined request while the
            // throttled response still owns the server's sendfile loop. H1's
            // single-task ordering fences the TX transfer: the server consumes
            // and applies the KeyUpdate before writing the following response.
            stream.conn.refresh_traffic_keys().unwrap();
            stream
                .write_all(b"GET /short HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            stream.read_exact(&mut received[split..]).unwrap();
            assert_eq!(received, expected);

            let second_head = read_h1_head(&mut stream);
            let second_len = h1_content_length(&second_head);
            let mut second = vec![0u8; second_len];
            stream.read_exact(&mut second).unwrap();
            assert_eq!(&second, b"short-after-key-update");
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tls_bridged(
                stream,
                peer,
                local,
                core,
                acceptor,
                crate::uring::ClientAuth::None,
                Some(template),
                CancellationToken::new(),
                ListenerBinding::default(),
            )
            .await;
        });
        client.join().unwrap();
        assert!(
            H1_SENDFILE_BYTES
                .load(Ordering::Relaxed)
                .saturating_sub(sendfile_before)
                >= expected_len as u64,
            "the TLS 1.3 kTLS range must traverse sendfile"
        );
        assert!(observed_direct.load(Ordering::Relaxed));
        drop(runtime);
        drop(tokio_runtime);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "ktls")]
    #[test]
    fn ktls_h1_sendfile_client_abort_reports_transport_error() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;

        let root = std::env::temp_dir().join(format!(
            "httpjet-ktls-abort-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("abort.bin");
        let file = std::fs::File::create(&source).unwrap();
        file.set_len(32 * 1024 * 1024).unwrap();
        drop(file);
        let (completion_tx, completion_rx) = std::sync::mpsc::channel();
        let (tokio_runtime, core, observed_direct) =
            ktls_file_test_core(&root, source, 32 * 1024 * 1024, Some(completion_tx));
        let (certificate, acceptor, template) = ktls_test_configs(&root);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = ktls_test_client(local, certificate);
            stream
                .write_all(b"GET /abort HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            let _ = read_h1_head(&mut stream);
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).unwrap();
            let reset = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: the option buffer is valid for this synchronous call and
            // the client owns the socket until the StreamOwned is dropped.
            let result = unsafe {
                libc::setsockopt(
                    stream.sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&reset as *const libc::linger).cast(),
                    std::mem::size_of_val(&reset) as libc::socklen_t,
                )
            };
            assert_eq!(result, 0);
            drop(stream);
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tls_bridged(
                stream,
                peer,
                local,
                core,
                acceptor,
                crate::uring::ClientAuth::None,
                Some(template),
                CancellationToken::new(),
                ListenerBinding::default(),
            )
            .await;
        });
        client.join().unwrap();
        assert_eq!(
            completion_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            hj_core::ResponseEnd::Error
        );
        assert!(observed_direct.load(std::sync::atomic::Ordering::Relaxed));
        drop(runtime);
        drop(tokio_runtime);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "ktls")]
    #[test]
    fn ktls_policy_tls12_connection_keeps_userspace_file_streaming() {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;

        let root = std::env::temp_dir().join(format!(
            "httpjet-ktls-tls12-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("tls12.bin");
        let bytes: Vec<u8> = (0..(512 * 1024 + 17))
            .map(|index| (index % 239) as u8)
            .collect();
        std::fs::write(&source, &bytes).unwrap();
        let source_len = bytes.len() as u64;
        let expected = bytes[117..=source_len as usize - 219].to_vec();
        let (tokio_runtime, core, observed_direct) =
            ktls_file_test_core(&root, source, source_len, None);
        let (certificate, acceptor, template) = ktls_test_configs(&root);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = ktls_test_client_version(local, certificate, false);
            stream
                .write_all(b"GET /range HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            let head = read_h1_head(&mut stream);
            assert_eq!(h1_content_length(&head), expected.len());
            assert_eq!(
                stream.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_2)
            );
            let mut body = vec![0u8; expected.len()];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(body, expected);
        });

        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tls_bridged(
                stream,
                peer,
                local,
                core,
                acceptor,
                crate::uring::ClientAuth::None,
                Some(template),
                CancellationToken::new(),
                ListenerBinding::default(),
            )
            .await;
        });
        client.join().unwrap();
        assert!(
            !observed_direct.load(Ordering::Relaxed),
            "TLS 1.2 must retain the userspace streaming path"
        );
        drop(runtime);
        drop(tokio_runtime);
        std::fs::remove_dir_all(root).unwrap();
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
                None,
            )
            .await;
        });
        client.join().unwrap();
    }

    fn h1_exchange(request: &'static [u8]) -> String {
        h1_exchange_on(websocket_test_core(), request)
    }

    fn h1_exchange_on(
        (_tokio_runtime, core): (tokio::runtime::Runtime, CoreHandler),
        request: &'static [u8],
    ) -> String {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(local).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream.write_all(request).unwrap();
            stream.flush().unwrap();
            let mut wire = Vec::new();
            let _ = stream.read_to_end(&mut wire);
            String::from_utf8_lossy(&wire).into_owned()
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
                None,
            )
            .await;
        });
        client.join().unwrap()
    }

    /// Regression (#608): 103 Early Hints go to HTTP/1.1 clients only; an HTTP/1.0
    /// client would read the interim head as the final response (RFC 9110 §15.2).
    #[test]
    fn h1_early_hints_are_never_sent_to_http10_clients() {
        let old = h1_exchange(b"GET /hint HTTP/1.0\r\nHost: x\r\n\r\n");
        assert!(old.starts_with("HTTP/1.1 200 OK\r\n"), "{old}");
        assert!(!old.contains(" 103 "), "{old}");
        assert!(old.ends_with("hinted"), "{old}");

        let new = h1_exchange(b"GET /hint HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(new.starts_with("HTTP/1.1 103 Early Hints\r\n"), "{new}");
        assert!(new.contains("\r\n\r\nHTTP/1.1 200 OK\r\n"), "{new}");
    }

    /// Regression (branch review of #599): accepted sockets carry TCP_USER_TIMEOUT so a
    /// peer that stops reading (zero-window probes forever) cannot park a write — and
    /// the responses it pins — with no timer able to fire.
    #[test]
    fn accepted_sockets_get_a_tcp_user_timeout() {
        use std::os::fd::AsRawFd;
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let client = std::thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
        let mut runtime = build_core_runtime().unwrap();
        let timeout = runtime.block_on(async move {
            let listener = TcpListener::from_std(std_listener).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            stream
                .set_tcp_user_timeout(Some(std::time::Duration::from_secs(7)))
                .unwrap();
            // SAFETY: `stream` owns this fd and outlives the borrow, which ends with
            // the getsockopt below.
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(stream.as_raw_fd()) };
            socket2::SockRef::from(&fd).tcp_user_timeout().unwrap()
        });
        drop(client.join().unwrap());
        assert_eq!(timeout, Some(std::time::Duration::from_secs(7)));
    }

    #[test]
    fn connection_close_wins_over_keep_alive() {
        fn keep_alive(wire: &[u8]) -> bool {
            let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
            let mut req = httparse::Request::new(&mut headers);
            let Ok(httparse::Status::Complete(head_len)) = req.parse(wire) else {
                panic!("fixture must parse");
            };
            match materialize_head(&req, head_len) {
                ParsedReq::Done { keep_alive, .. } => keep_alive,
                _ => panic!("expected Done"),
            }
        }
        assert!(!keep_alive(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close, keep-alive\r\n\r\n"
        ));
        assert!(!keep_alive(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n"
        ));
        assert!(keep_alive(
            b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"
        ));
        assert!(keep_alive(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    }

    /// Regression (branch review of #608): an HTTP/1.0 request asking for a WebSocket
    /// upgrade is served normally; the Upgrade is ignored and no 101 is ever sent.
    #[test]
    fn http10_upgrade_request_is_served_without_switching() {
        let wire = h1_exchange(
            b"GET /sees-upgrade HTTP/1.0\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        );
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{wire}");
        assert!(!wire.contains(" 101 "), "{wire}");
        assert!(wire.ends_with("upgrade=no"), "{wire}");
    }

    /// Regression (branch review of #609): an HTTP/1.0 client that asked for keep-alive
    /// still gets the connection closed after a close-delimited body, or it could never
    /// tell where the body ends.
    #[test]
    fn http10_keep_alive_close_delimited_body_closes_the_connection() {
        let started = std::time::Instant::now();
        let wire = h1_exchange_on(
            websocket_test_core_with(100),
            b"GET /sse HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the server must close after the body, not wait for another request"
        );
        let head = wire.to_ascii_lowercase();
        assert!(!head.contains("transfer-encoding"), "{wire}");
        assert!(head.contains("connection: close\r\n"), "{wire}");
        assert!(wire.ends_with("\r\n\r\ndata: 1\n\ndata: 2\n\n"), "{wire}");
    }

    #[test]
    fn materialize_head_records_http10() {
        fn parse(wire: &[u8]) -> ParsedReq {
            let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(wire) {
                Ok(httparse::Status::Complete(head_len)) => materialize_head(&req, head_len),
                other => panic!("fixture must parse-complete, got {other:?}"),
            }
        }
        let http10 = |p: &ParsedReq| match p {
            ParsedReq::Done { http10, .. } => Some(*http10),
            _ => None,
        };
        assert_eq!(http10(&parse(b"GET / HTTP/1.0\r\n\r\n")), Some(true));
        assert_eq!(
            http10(&parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
            Some(false)
        );
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
    fn persistent_accept_errors_back_off() {
        assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(
            libc::EMFILE
        )));
        assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(
            libc::ENOBUFS
        )));
        assert!(accept_error_is_transient(&io::Error::from_raw_os_error(
            libc::ECONNABORTED
        )));
    }

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

        // #671: repeated Cookie lines reach the pipeline as one `; `-joined value.
        match parse(b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nCookie: xf_style_id=7\r\n\r\n") {
            ParsedReq::Done { headers, .. } => {
                let cookies: Vec<_> = headers.get_all("cookie").iter().collect();
                assert_eq!(cookies, ["a=1; xf_style_id=7"]);
            }
            _ => panic!("expected Done"),
        }

        // #669: Transfer-Encoding on HTTP/1.0 is faulty framing.
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
            )),
            Some(BodyFraming::Reject)
        );
        assert_eq!(
            framing(&parse(
                b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            )),
            Some(BodyFraming::Chunked)
        );

        // RFC 9112 §3.2 target forms and Host.
        let target = |wire: &[u8]| match parse(wire) {
            ParsedReq::Done { uri, headers, .. } => Some((
                uri.to_string(),
                headers
                    .get(http::header::HOST)
                    .map(|h| h.to_str().unwrap().to_owned()),
            )),
            _ => None,
        };
        assert_eq!(
            target(b"GET http://a.test/x?y=1 HTTP/1.1\r\nHost: b.test\r\n\r\n"),
            Some(("/x?y=1".into(), Some("a.test".into()))),
            "absolute-form: origin-form URI, authority replaces Host"
        );
        assert_eq!(
            target(b"GET http://a.test HTTP/1.1\r\n\r\n"),
            Some(("/".into(), Some("a.test".into()))),
            "absolute-form supplies the missing Host"
        );
        assert_eq!(
            target(b"OPTIONS * HTTP/1.1\r\nHost: a.test\r\n\r\n"),
            Some(("*".into(), Some("a.test".into())))
        );
        assert_eq!(
            target(b"GET / HTTP/1.0\r\n\r\n"),
            Some(("/".into(), None)),
            "HTTP/1.0 may omit Host"
        );
        for bad in [
            &b"GET * HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
            b"GET a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET ftp://a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET http://u@a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET /x#frag HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: \r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: u@a.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: [::1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\xffb\r\n\r\n",
        ] {
            assert!(
                matches!(parse(bad), ParsedReq::Bad),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert!(matches!(
            parse(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n"),
            ParsedReq::MethodNotAllowed
        ));

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

    // ---- (#1034) shutdown drain ----

    const GRACE_SLACK: std::time::Duration = std::time::Duration::from_millis(1500);

    /// Serve one connection with `handle_h1_bridged` under `shutdown`; returns the
    /// address and a receiver for the instant the handler returned.
    fn serve_h1_once(
        core: CoreHandler,
        shutdown: CancellationToken,
    ) -> (SocketAddr, std::sync::mpsc::Receiver<std::time::Instant>) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut runtime = build_core_runtime().unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(std_listener).unwrap();
                let (stream, peer) = listener.accept().await.unwrap();
                handle_h1_bridged(
                    stream,
                    Vec::new(),
                    BridgeCtx::plain(peer, local, Proto::Http1),
                    core,
                    shutdown,
                    None,
                )
                .await;
                let _ = done.send(std::time::Instant::now());
            });
        });
        (local, finished)
    }

    fn connect(address: SocketAddr) -> std::net::TcpStream {
        let stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        stream
    }

    #[test]
    fn shutdown_ends_a_backend_idle_h1_stream_without_its_terminator() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core();
        let shutdown = CancellationToken::new();
        let (address, finished) = serve_h1_once(core, shutdown.clone());
        let mut stream = connect(address);
        stream
            .write_all(b"GET /endless HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let head = String::from_utf8(read_h1_head(&mut stream)).unwrap();
        assert!(
            head.to_ascii_lowercase()
                .contains("transfer-encoding: chunked\r\n"),
            "{head}"
        );
        let first = b"9\r\ndata: 1\n\n\r\n";
        let mut chunk = vec![0u8; first.len()];
        stream.read_exact(&mut chunk).unwrap();
        assert_eq!(chunk, first);

        let signalled = std::time::Instant::now();
        shutdown.cancel();
        let mut rest = Vec::new();
        stream
            .read_to_end(&mut rest)
            .expect("a truncation is a clean close, not a reset");
        let waited = signalled.elapsed();
        assert!(
            rest.is_empty(),
            "a truncated stream must not end with the terminator: {:?}",
            String::from_utf8_lossy(&rest)
        );
        assert!(
            waited + std::time::Duration::from_millis(50) >= SHUTDOWN_IDLE_GRACE,
            "ended before the idle grace: {waited:?}"
        );
        assert!(waited < SHUTDOWN_IDLE_GRACE + GRACE_SLACK, "{waited:?}");
        let returned = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the connection must end with the stream");
        assert!(returned - signalled < SHUTDOWN_IDLE_GRACE + GRACE_SLACK);
    }

    #[test]
    fn shutdown_lets_a_producing_h1_stream_finish() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core();
        let shutdown = CancellationToken::new();
        let (address, finished) = serve_h1_once(core, shutdown.clone());
        let mut stream = connect(address);
        stream
            .write_all(b"GET /trickle HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let _head = read_h1_head(&mut stream);
        let first = b"9\r\ndata: a\n\n\r\n";
        let mut chunk = vec![0u8; first.len()];
        stream.read_exact(&mut chunk).unwrap();
        assert_eq!(chunk, first);
        shutdown.cancel();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&rest),
            "9\r\ndata: b\n\n\r\n9\r\ndata: c\n\n\r\n9\r\ndata: d\n\n\r\n0\r\n\r\n",
            "a stream still producing must complete during the drain"
        );
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the connection closes once the response is done");
    }

    #[test]
    fn shutdown_completes_an_in_flight_h1_request_with_connection_close() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core_with(100);
        let shutdown = CancellationToken::new();
        let (address, finished) = serve_h1_once(core, shutdown.clone());
        let mut stream = connect(address);
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        shutdown.cancel();
        let mut wire = Vec::new();
        stream.read_to_end(&mut wire).unwrap();
        let wire = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(wire.starts_with("http/1.1 200 ok\r\n"), "{wire}");
        assert!(wire.contains("connection: close\r\n"), "{wire}");
        assert!(wire.ends_with("slow-done"), "{wire}");
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }

    #[test]
    fn a_draining_worker_answers_its_in_flight_h1_request_with_connection_close() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core_with(100);
        let (group, address) = spawn_test_http_group(core);
        let mut stream = connect(address);
        let mut wire = Vec::new();
        let mut buf = [0u8; 4096];
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        while !wire.ends_with(b"slow-done") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "closed before the first response");
            wire.extend_from_slice(&buf[..n]);
        }
        let first = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(!first.contains("connection: close"), "{first}");

        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let stopper = std::thread::spawn(move || drop(group));
        wire.clear();
        stream.read_to_end(&mut wire).unwrap();
        stopper.join().unwrap();
        let second = String::from_utf8_lossy(&wire).to_ascii_lowercase();
        assert!(second.starts_with("http/1.1 200 ok\r\n"), "{second}");
        assert!(second.contains("connection: close\r\n"), "{second}");
        assert!(second.ends_with("slow-done"), "{second}");
    }

    /// One production per-core plaintext worker (`per_core_bridged`) around `core`.
    fn spawn_test_http_group(core: CoreHandler) -> (WorkerGroup, SocketAddr) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let local = std_listener.local_addr().unwrap();
        let mut group = WorkerGroup::new(&CancellationToken::new());
        let activation = group.activation_gate();
        let accept_stopped = group.register_acceptor(&std_listener).unwrap();
        let active = core.holder.load().metrics.active_conns.clone();
        let (ready, ready_rx) = std::sync::mpsc::channel();
        group
            .spawn(
                std::thread::Builder::new().name("hj-uring-drain-test".into()),
                move |shutdown| {
                    per_core_bridged(
                        0,
                        std_listener,
                        local,
                        core,
                        shutdown,
                        active,
                        ready,
                        activation,
                        ListenerBinding::default(),
                        accept_stopped,
                    )
                },
            )
            .unwrap();
        wait_for_worker_readiness("test", 1, ready_rx).unwrap();
        group.activate();
        (group, local)
    }

    /// One production per-core TLS worker (`per_core_https`) around `core`.
    fn spawn_test_https_group(core: CoreHandler) -> (WorkerGroup, SocketAddr) {
        hj_tls::install_crypto_provider().unwrap();
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(signed.signing_key.serialize_der()).unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![signed.cert.der().clone()], key)
            .unwrap();
        let acceptor: monoio_rustls::TlsAcceptor = Arc::new(tls).into();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let local = std_listener.local_addr().unwrap();
        let mut group = WorkerGroup::new(&CancellationToken::new());
        let activation = group.activation_gate();
        let accept_stopped = group.register_acceptor(&std_listener).unwrap();
        let active = core.holder.load().metrics.active_conns.clone();
        let (ready, ready_rx) = std::sync::mpsc::channel();
        group
            .spawn(
                std::thread::Builder::new().name("hj-uring-tls-drain-test".into()),
                move |shutdown| {
                    per_core_https(
                        0,
                        std_listener,
                        local,
                        core,
                        acceptor,
                        ClientAuth::None,
                        None,
                        shutdown,
                        active,
                        ready,
                        activation,
                        ListenerBinding::default(),
                        accept_stopped,
                    )
                },
            )
            .unwrap();
        wait_for_worker_readiness("test", 1, ready_rx).unwrap();
        group.activate();
        (group, local)
    }

    fn wait_for_connections(core: &CoreHandler, count: u64) {
        let active = core.holder.load().metrics.active_conns.clone();
        let started = std::time::Instant::now();
        while active.load(std::sync::atomic::Ordering::Relaxed) < count {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "connections were never accepted"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// Stops the group (cancel + join, as `finish_shutdown` does) and times the drain.
    fn timed_drain(group: WorkerGroup) -> std::time::Duration {
        let started = std::time::Instant::now();
        drop(group);
        started.elapsed()
    }

    #[test]
    fn silent_pre_request_connections_do_not_hold_the_drain() {
        use std::io::Write;

        let (_tokio_runtime, core) = websocket_test_core();
        let (group, address) = spawn_test_http_group(core.clone());
        // Waiting in the H1/h2c sniff, inside a partial H1 head, and mid h2c preface.
        let _silent = connect(address);
        let mut partial = connect(address);
        partial.write_all(b"GET / HTTP/1.1\r\nHo").unwrap();
        let mut preface = connect(address);
        preface.write_all(&H2_PREFACE[..10]).unwrap();
        wait_for_connections(&core, 3);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let drained = timed_drain(group);
        assert!(
            drained < std::time::Duration::from_secs(1),
            "pre-request connections held the drain for {drained:?}"
        );

        let (_tokio_runtime, core) = websocket_test_core();
        let (group, address) = spawn_test_https_group(core.clone());
        // Connected, never sends a ClientHello.
        let _silent = connect(address);
        wait_for_connections(&core, 1);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let drained = timed_drain(group);
        assert!(
            drained < std::time::Duration::from_secs(1),
            "a pre-ClientHello connection held the drain for {drained:?}"
        );
    }

    #[test]
    fn an_endless_h1_stream_holds_the_drain_only_for_the_idle_grace() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core();
        let (group, address) = spawn_test_http_group(core);
        let mut stream = connect(address);
        stream
            .write_all(b"GET /endless HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let _head = read_h1_head(&mut stream);
        let mut chunk = [0u8; 14];
        stream.read_exact(&mut chunk).unwrap();
        let drained = timed_drain(group);
        assert!(
            drained + std::time::Duration::from_millis(50) >= SHUTDOWN_IDLE_GRACE,
            "{drained:?}"
        );
        assert!(
            drained < SHUTDOWN_IDLE_GRACE + GRACE_SLACK,
            "an endless stream held the drain for {drained:?}"
        );
    }

    /// Minimal h2c client frames: preface, SETTINGS and one GET for `path` on stream 1.
    fn h2c_get(path: &str) -> Vec<u8> {
        let mut wire = H2_PREFACE.to_vec();
        hj_h2::frame::write_settings(&mut wire, &[]);
        let mut encoder = hj_h2::hpack::Encoder::new();
        let mut block = Vec::new();
        for (name, value) in [
            (":method", "GET"),
            (":path", path),
            (":scheme", "http"),
            (":authority", "x"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        hj_h2::frame::write_frame(
            &mut wire,
            hj_h2::frame::kind::HEADERS,
            hj_h2::frame::flags::END_HEADERS | hj_h2::frame::flags::END_STREAM,
            1,
            &block,
        );
        wire
    }

    /// Server frames (kind, flags, stream, payload) parsed from `raw`.
    fn h2_frames(raw: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut at = 0;
        while let Some(header) = raw.get(at..at + hj_h2::frame::FrameHeader::LEN) {
            let header = hj_h2::frame::FrameHeader::parse(header).unwrap();
            let start = at + hj_h2::frame::FrameHeader::LEN;
            let Some(payload) = raw.get(start..start + header.length as usize) else {
                break;
            };
            frames.push((
                header.kind,
                header.flags,
                header.stream_id,
                payload.to_vec(),
            ));
            at = start + header.length as usize;
        }
        frames
    }

    #[test]
    fn an_endless_h2c_stream_is_reset_after_the_idle_grace() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = websocket_test_core();
        let (group, address) = spawn_test_http_group(core);
        let mut stream = connect(address);
        stream.write_all(&h2c_get("/endless")).unwrap();
        // The first event's DATA arrives before shutdown is signalled.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        while !raw.windows(9).any(|w| w == b"data: 1\n\n") {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "connection closed before the first event");
            raw.extend_from_slice(&buf[..n]);
        }
        let mut reader = stream.try_clone().unwrap();
        let rest = std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = reader.read_to_end(&mut rest);
            rest
        });
        let drained = timed_drain(group);
        assert!(
            drained + std::time::Duration::from_millis(50) >= SHUTDOWN_IDLE_GRACE,
            "{drained:?}"
        );
        assert!(
            drained < SHUTDOWN_IDLE_GRACE + GRACE_SLACK,
            "an endless h2 stream held the drain for {drained:?}"
        );
        raw.extend_from_slice(&rest.join().unwrap());
        let frames = h2_frames(&raw);
        assert!(
            frames
                .iter()
                .any(|(kind, ..)| *kind == hj_h2::frame::kind::GOAWAY),
            "{frames:?}"
        );
        let reset = frames
            .iter()
            .find(|(kind, _, sid, _)| *kind == hj_h2::frame::kind::RST_STREAM && *sid == 1)
            .expect("the idle stream is reset");
        assert_eq!(
            u32::from_be_bytes(reset.3[..4].try_into().unwrap()),
            hj_h2::frame::error_code::CANCEL
        );
        assert!(
            !frames
                .iter()
                .any(|(kind, flags, sid, _)| *kind == hj_h2::frame::kind::DATA
                    && *sid == 1
                    && flags & hj_h2::frame::flags::END_STREAM != 0),
            "a truncated stream must not end cleanly: {frames:?}"
        );
    }

    #[test]
    fn next_stream_chunk_abandons_only_an_idle_body_after_shutdown() {
        let mut runtime = build_core_runtime().unwrap();
        runtime.block_on(async {
            let shutdown = CancellationToken::new();
            let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(4);
            let mut stopping = false;
            tx.try_send(1).unwrap();
            assert_eq!(
                next_stream_chunk(&mut rx, &shutdown, &mut stopping).await,
                Ok(Some(1))
            );
            shutdown.cancel();
            tx.try_send(2).unwrap();
            // A chunk already waiting is delivered after the signal.
            assert_eq!(
                next_stream_chunk(&mut rx, &shutdown, &mut stopping).await,
                Ok(Some(2))
            );
            let started = std::time::Instant::now();
            assert_eq!(
                next_stream_chunk(&mut rx, &shutdown, &mut stopping).await,
                Err(())
            );
            assert!(
                started.elapsed() + std::time::Duration::from_millis(50) >= SHUTDOWN_IDLE_GRACE
            );
            assert!(stopping);
            drop(tx);
            assert_eq!(
                next_stream_chunk(&mut rx, &shutdown, &mut stopping).await,
                Ok(None)
            );
        });
    }

    // ---- (#1035) request-body progress deadline ----

    const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    fn body_deadline_core(ceiling: std::time::Duration) -> (tokio::runtime::Runtime, CoreHandler) {
        websocket_test_core_serve(
            |config| config.tuning.conn_timeout = BODY_TIMEOUT,
            |serve| serve.request_body_ceiling = ceiling,
        )
    }

    /// POSTs `chunks` x `chunk` body bytes to `/upload-len`, one chunk every `gap`, and
    /// returns the reply with how long after the head the handler returned.
    fn paced_h1_upload(
        ceiling: std::time::Duration,
        chunk: usize,
        chunks: usize,
        gap: std::time::Duration,
        chunked: bool,
    ) -> (String, std::time::Duration) {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = body_deadline_core(ceiling);
        let (address, finished) = serve_h1_once(core, CancellationToken::new());
        let mut stream = connect(address);
        let framing = if chunked {
            "Transfer-Encoding: chunked".to_owned()
        } else {
            format!("Content-Length: {}", chunk * chunks)
        };
        let head = format!(
            "POST /upload-len HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{framing}\r\n\r\n"
        );
        stream.write_all(head.as_bytes()).unwrap();
        let sent_head = std::time::Instant::now();
        let block = vec![b'x'; chunk];
        for index in 0..chunks {
            let mut wire = Vec::new();
            if chunked {
                wire.extend_from_slice(format!("{chunk:x}\r\n").as_bytes());
            }
            wire.extend_from_slice(&block);
            if chunked {
                wire.extend_from_slice(b"\r\n");
                if index + 1 == chunks {
                    wire.extend_from_slice(b"0\r\n\r\n");
                }
            }
            if stream.write_all(&wire).is_err() {
                break;
            }
            if index + 1 < chunks {
                std::thread::sleep(gap);
            }
        }
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        let returned = finished
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the connection handler returns");
        (String::from_utf8(reply).unwrap(), returned - sent_head)
    }

    #[test]
    fn h1_steady_upload_outlasting_the_timeout_is_answered() {
        for chunked in [false, true] {
            // 16 KiB every 400 ms for 2.4 s: past twice the 1 s connTimeout.
            let (reply, took) = paced_h1_upload(
                hj_core::body_deadline::BODY_DEADLINE_CEILING,
                16 * 1024,
                7,
                std::time::Duration::from_millis(400),
                chunked,
            );
            assert!(
                reply.starts_with("HTTP/1.1 200 OK\r\n"),
                "chunked={chunked}: {reply:?}"
            );
            assert!(
                reply.ends_with("\r\n\r\n114688"),
                "chunked={chunked}: {reply:?}"
            );
            assert!(took > 2 * BODY_TIMEOUT, "chunked={chunked}: {took:?}");
        }
    }

    #[test]
    fn h1_trickled_upload_is_closed_at_the_timeout() {
        let (reply, took) = paced_h1_upload(
            hj_core::body_deadline::BODY_DEADLINE_CEILING,
            1,
            100,
            std::time::Duration::from_millis(100),
            false,
        );
        assert_eq!(reply, "", "a stalled body is closed without a response");
        assert!(
            took >= BODY_TIMEOUT - std::time::Duration::from_millis(50)
                && took < BODY_TIMEOUT + std::time::Duration::from_millis(700),
            "{took:?}"
        );
    }

    #[test]
    fn h1_steady_upload_is_closed_at_the_ceiling() {
        let ceiling = std::time::Duration::from_millis(1500);
        let (reply, took) = paced_h1_upload(
            ceiling,
            16 * 1024,
            10,
            std::time::Duration::from_millis(300),
            false,
        );
        assert_eq!(reply, "", "the ceiling closes without a response");
        assert!(
            took >= ceiling - std::time::Duration::from_millis(50)
                && took < ceiling + std::time::Duration::from_millis(700),
            "{took:?}"
        );
    }

    // ---- (#1036) lingering close ----

    fn small_body_core() -> (tokio::runtime::Runtime, CoreHandler) {
        websocket_test_core_config(|config| config.tuning.max_req_body_size = 1024 * 1024)
    }

    /// Streams a 10 MiB body against the 1 MiB cap without reading, then reads the reply.
    fn upload_then_read(address: SocketAddr, chunked: bool) -> String {
        use std::io::{Read, Write};

        const BODY: usize = 10 * 1024 * 1024;
        let mut stream = connect(address);
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        let head = if chunked {
            "POST /body HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned()
        } else {
            format!("POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: {BODY}\r\n\r\n")
        };
        stream.write_all(head.as_bytes()).unwrap();
        let block = vec![b'x'; 64 * 1024];
        for _ in 0..BODY / block.len() {
            if chunked {
                stream.write_all(b"10000\r\n").unwrap();
            }
            stream
                .write_all(&block)
                .expect("the server must keep reading the refused body");
            if chunked {
                stream.write_all(b"\r\n").unwrap();
            }
        }
        if chunked {
            stream.write_all(b"0\r\n\r\n").unwrap();
        }
        let mut reply = Vec::new();
        stream
            .read_to_end(&mut reply)
            .expect("the refusal must arrive intact and end in EOF, not a reset");
        String::from_utf8(reply).unwrap()
    }

    #[test]
    fn refused_body_returns_its_budget_before_the_linger() {
        let budget = Arc::new(hj_core::budget::BodyBufferBudget::new(8 * 1024 * 1024));
        let mut lease = Some(hj_core::budget::BodyBufferLease::new(budget.clone()));
        assert!(lease.as_mut().unwrap().reserve(2 * 1024 * 1024));
        let mut acc = vec![b'x'; 2 * 1024 * 1024];
        assert_eq!(budget.in_flight(), 2 * 1024 * 1024);
        release_refused_body(&mut lease, &mut acc);
        assert_eq!(budget.in_flight(), 0, "the reservation is returned at once");
        assert!(
            lease.is_none() && acc.capacity() == 0,
            "the buffer is freed"
        );
    }

    #[test]
    fn early_h1_refusal_lingers_until_the_client_has_sent_its_body() {
        for chunked in [false, true] {
            let (_tokio_runtime, core) = small_body_core();
            let (address, finished) = serve_h1_once(core, CancellationToken::new());
            let reply = upload_then_read(address, chunked);
            assert_eq!(
                reply,
                "HTTP/1.1 413 Payload Too Large\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
                "chunked={chunked}"
            );
            finished
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the lingering close ends at the client's EOF");
        }
    }

    #[test]
    fn lingering_close_yields_to_the_shutdown_grace() {
        use std::io::{Read, Write};

        let (_tokio_runtime, core) = small_body_core();
        let shutdown = CancellationToken::new();
        let (address, finished) = serve_h1_once(core, shutdown.clone());
        let mut stream = connect(address);
        // Over the cap; the client then neither sends the body nor closes.
        stream
            .write_all(b"POST /body HTTP/1.1\r\nHost: x\r\nContent-Length: 2097152\r\n\r\n")
            .unwrap();
        let head = read_h1_head(&mut stream);
        assert!(head.starts_with(b"HTTP/1.1 413 "));
        let mut eof = [0u8; 1];
        assert_eq!(stream.read(&mut eof).unwrap(), 0, "the server half-closes");
        let signalled = std::time::Instant::now();
        shutdown.cancel();
        let returned = finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let waited = returned - signalled;
        assert!(waited < LINGER_TIME, "{waited:?}");
        assert!(waited < SHUTDOWN_IDLE_GRACE + GRACE_SLACK, "{waited:?}");
    }

    // ---- plaintext mTLS gate at the request head ----

    /// Both H1 head serializers write into one exactly sized allocation.
    #[test]
    fn h1_response_heads_are_allocated_once() {
        let mut headers = http::HeaderMap::new();
        for i in 0..40 {
            headers.append(
                http::HeaderName::from_bytes(format!("x-forum-header-{i}").as_bytes()).unwrap(),
                http::HeaderValue::from_static("value-padding-value-padding-value-padding"),
            );
        }
        let needed = h1_head_capacity(&headers);
        for (status, body_len, is_head, keep_alive) in [
            (http::StatusCode::OK, 12_345_678_901usize, false, true),
            (http::StatusCode::NOT_FOUND, 0, true, false),
            (http::StatusCode::from_u16(599).unwrap(), 1, false, false),
        ] {
            let head = serialize_h1_response_head(status, &headers, body_len, is_head, keep_alive);
            assert_eq!(head.capacity(), needed, "{status}: the head regrew");
        }
        for framing in [
            H1ResponseFraming::ContentLength(u64::MAX),
            H1ResponseFraming::Chunked,
            H1ResponseFraming::None,
        ] {
            let head = serialize_h1_head_framed(http::StatusCode::OK, &headers, framing, false);
            assert_eq!(head.capacity(), needed, "framed head regrew");
        }
    }

    /// The h2c head-time refusal sends a bodiless 301, so the shared gate must build (and
    /// access-log) it without the HTML body the H1 path writes.
    #[test]
    fn bodiless_plaintext_redirect_carries_no_body() {
        let (_tokio_runtime, core) = mtls_gated_core();
        let state = core.holder.load_full();
        let peer: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        let probe = |bodiless| {
            let mut req = http::Request::builder()
                .method("POST")
                .uri("/upload")
                .header(http::header::HOST, "gated.test")
                .body(hj_core::empty_incoming())
                .unwrap();
            crate::pipeline::plaintext_mtls_redirect(
                &state,
                &core.listener_name,
                peer,
                Proto::Http2,
                &mut req,
                bodiless,
            )
            .expect("a gated vhost redirects a non-exempt plaintext peer")
        };
        let h1 = probe(false);
        assert_eq!(h1.status(), http::StatusCode::MOVED_PERMANENTLY);
        assert!(h1.body().content_length().is_some_and(|len| len > 0));
        let h2c = probe(true);
        assert_eq!(h2c.status(), http::StatusCode::MOVED_PERMANENTLY);
        assert_eq!(h2c.body().content_length(), Some(0));
        assert_eq!(h2c.headers()[http::header::CONTENT_LENGTH], "0");
        assert!(h2c.headers().get(http::header::CONTENT_TYPE).is_none());
        assert_eq!(
            h2c.headers()[http::header::LOCATION],
            h1.headers()[http::header::LOCATION]
        );
    }

    /// `gated.test` requires a client certificate on the secure listener; `open.test`
    /// does not. Both are mapped on the plaintext `test` listener.
    fn mtls_gated_core() -> (tokio::runtime::Runtime, CoreHandler) {
        use hj_core::config::{Listener, ListenerTls, VHostConfig, VHostDecl, VhostMap};

        websocket_test_core_config(|config| {
            let root = config.server_root.clone();
            for name in ["gated", "open"] {
                config.vhosts.insert(
                    name.into(),
                    VHostDecl {
                        name: name.into(),
                        vh_root: root.clone(),
                        config_file: std::path::PathBuf::new(),
                        allow_symbol_link: Some(true),
                        restrained: false,
                        enable_script: true,
                        config: Some(Arc::new(VHostConfig {
                            doc_root: root.clone(),
                            ..VHostConfig::default()
                        })),
                    },
                );
                config.vhost_order.push(name.into());
            }
            let map = |vhost: &str| VhostMap {
                vhost: vhost.into(),
                domains: vec![format!("{vhost}.test")],
            };
            config.listeners = vec![
                Listener {
                    name: "test".into(),
                    address: "127.0.0.1:0".into(),
                    secure: false,
                    vhost_map: vec![map("gated"), map("open")],
                    tls: None,
                    uds_path: None,
                    proxy_protocol: false,
                    proxy_protocol_peers: vec![],
                },
                Listener {
                    name: "mtls".into(),
                    address: "127.0.0.1:0".into(),
                    secure: true,
                    vhost_map: vec![map("gated")],
                    tls: Some(ListenerTls {
                        key_file: std::path::PathBuf::new(),
                        cert_file: std::path::PathBuf::new(),
                        cert_chain: false,
                        ca_cert_file: None,
                        client_verify: 2,
                        verify_depth: 1,
                        enable_stapling: false,
                        crl_file: None,
                    }),
                    uds_path: None,
                    proxy_protocol: false,
                    proxy_protocol_peers: vec![],
                },
            ];
        })
    }

    const DIRECT_PEER: ([u8; 4], u16) = ([198, 51, 100, 20], 40000);

    /// [`serve_h1_once`] with the connection attributed to `peer` (the test socket
    /// itself is loopback, which the gate exempts).
    fn serve_h1_once_from(
        core: CoreHandler,
        peer: Option<SocketAddr>,
    ) -> (SocketAddr, std::sync::mpsc::Receiver<std::time::Instant>) {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut runtime = build_core_runtime().unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(std_listener).unwrap();
                let (stream, real_peer) = listener.accept().await.unwrap();
                handle_h1_bridged(
                    stream,
                    Vec::new(),
                    BridgeCtx::plain(peer.unwrap_or(real_peer), local, Proto::Http1),
                    core,
                    CancellationToken::new(),
                    None,
                )
                .await;
                let _ = done.send(std::time::Instant::now());
            });
        });
        (local, finished)
    }

    fn upload_head(host: &str, chunked: bool) -> String {
        let framing = if chunked {
            "Transfer-Encoding: chunked".to_owned()
        } else {
            "Content-Length: 1048576".to_owned()
        };
        format!(
            "POST /upload-len?x=1 HTTP/1.1\r\nHost: {host}\r\nExpect: 100-continue\r\n{framing}\r\n\r\n"
        )
    }

    fn without_date(wire: &[u8]) -> String {
        String::from_utf8_lossy(wire)
            .split("\r\n")
            .filter(|line| !line.to_ascii_lowercase().starts_with("date:"))
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    #[test]
    fn gated_plaintext_upload_is_redirected_before_100_continue_or_its_body() {
        use std::io::{Read, Write};

        for chunked in [false, true] {
            let (tokio_runtime, core) = mtls_gated_core();
            let state = core.holder.load_full();
            assert!(state.mtls_required_vhosts.contains("gated"));
            let (address, finished) = serve_h1_once_from(core, Some(SocketAddr::from(DIRECT_PEER)));
            let mut stream = connect(address);
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            // The head only: a client honoring Expect waits for 100 before its body.
            stream
                .write_all(upload_head("gated.test", chunked).as_bytes())
                .unwrap();
            let mut wire = Vec::new();
            stream
                .read_to_end(&mut wire)
                .expect("the redirect arrives without waiting for a body");
            let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
            assert!(
                text.starts_with("http/1.1 301 moved permanently\r\n"),
                "chunked={chunked}: no 100 Continue precedes the redirect: {text:?}"
            );
            assert!(
                text.contains("\r\nlocation: https://gated.test/upload-len?x=1\r\n"),
                "{text:?}"
            );
            assert!(text.contains("\r\nconnection: close\r\n"), "{text:?}");
            drop(stream);
            finished
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the connection closes after the redirect");

            // Byte-identical to the full pipeline's own gate response, framed for close.
            let mut req = http::Request::new(hj_core::empty_incoming());
            *req.method_mut() = http::Method::POST;
            *req.uri_mut() = "/upload-len?x=1".parse().unwrap();
            req.headers_mut().insert(
                http::header::HOST,
                http::HeaderValue::from_static("gated.test"),
            );
            let expected = tokio_runtime.block_on(async {
                let response = crate::pipeline::handle(
                    state.clone(),
                    "test",
                    SocketAddr::from(DIRECT_PEER).ip(),
                    address,
                    DIRECT_PEER.1,
                    false,
                    false,
                    false,
                    None,
                    Proto::Http1,
                    None,
                    req,
                )
                .await;
                let response = bridge::fast_response(hj_core::stamp_date(response), false).await;
                let bridge::BridgeBody::Full(body) = response.body else {
                    panic!("the redirect is a full body");
                };
                let mut expected = serialize_h1_response_head(
                    response.status,
                    &response.headers,
                    body.len(),
                    false,
                    false,
                );
                expected.extend_from_slice(&body);
                expected
            });
            assert_eq!(without_date(&wire), without_date(&expected));
        }
    }

    #[test]
    fn exempt_or_ungated_plaintext_uploads_still_get_100_continue_and_dispatch() {
        use std::io::{Read, Write};

        for (host, peer) in [
            ("gated.test", None),
            ("open.test", Some(SocketAddr::from(DIRECT_PEER))),
        ] {
            let (_tokio_runtime, core) = mtls_gated_core();
            let (address, _finished) = serve_h1_once_from(core, peer);
            let mut stream = connect(address);
            stream
                .write_all(
                    format!(
                        "POST /upload-len HTTP/1.1\r\nHost: {host}\r\nExpect: 100-continue\r\n\
                         Connection: close\r\nContent-Length: 5\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            let interim = read_h1_head(&mut stream);
            assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n", "{host}");
            stream.write_all(b"hello").unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            let reply = String::from_utf8(reply).unwrap();
            assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{host}: {reply}");
            assert!(reply.ends_with("\r\n\r\n5"), "{host}: {reply}");
        }
    }

    /// An h2c connection served by [`serve_h2_bridged`], attributed to `peer`.
    fn serve_h2c_once_from(core: CoreHandler, peer: Option<SocketAddr>) -> SocketAddr {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = std_listener.local_addr().unwrap();
        std_listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut runtime = build_core_runtime().unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(std_listener).unwrap();
                let (stream, real_peer) = listener.accept().await.unwrap();
                serve_h2_bridged(
                    stream,
                    Vec::new(),
                    BridgeCtx::plain(peer.unwrap_or(real_peer), local, Proto::Http2),
                    core,
                    CancellationToken::new(),
                    None,
                )
                .await;
            });
        });
        local
    }

    /// Request HEADERS (without END_STREAM) for a 5-byte POST to `host`/upload-len.
    fn h2c_upload_head(
        encoder: &mut hj_h2::hpack::Encoder,
        wire: &mut Vec<u8>,
        sid: u32,
        host: &str,
    ) {
        let mut block = Vec::new();
        for (name, value) in [
            (":method", "POST"),
            (":path", "/upload-len"),
            (":scheme", "http"),
            (":authority", host),
            ("expect", "100-continue"),
            ("content-length", "5"),
        ] {
            encoder.encode_header(&mut block, name, value);
        }
        hj_h2::frame::write_frame(
            wire,
            hj_h2::frame::kind::HEADERS,
            hj_h2::frame::flags::END_HEADERS,
            sid,
            &block,
        );
    }

    /// Reads server frames until a PING ACK, returning every `sid` frame as (kind, flags,
    /// decoded header fields, payload). Decodes every HEADERS block to keep `decoder` in sync.
    fn h2c_frames_until_ping_ack(
        stream: &mut std::net::TcpStream,
        decoder: &mut hj_h2::hpack::Decoder,
        sid: u32,
    ) -> Vec<(u8, u8, Vec<(String, String)>, Vec<u8>)> {
        use std::io::Read;

        let mut frames = Vec::new();
        loop {
            let mut head = [0u8; hj_h2::frame::FrameHeader::LEN];
            stream.read_exact(&mut head).unwrap();
            let header = hj_h2::frame::FrameHeader::parse(&head).unwrap();
            let mut payload = vec![0u8; header.length as usize];
            stream.read_exact(&mut payload).unwrap();
            let mut fields = Vec::new();
            if header.kind == hj_h2::frame::kind::HEADERS {
                decoder
                    .decode(&payload, |n, v| fields.push((n.to_owned(), v.to_owned())))
                    .unwrap();
            }
            assert_ne!(header.kind, hj_h2::frame::kind::GOAWAY, "{frames:?}");
            if header.kind == hj_h2::frame::kind::PING
                && header.flags & hj_h2::frame::flags::ACK != 0
            {
                return frames;
            }
            if header.stream_id == sid {
                frames.push((header.kind, header.flags, fields, payload));
            }
        }
    }

    fn h2c_client(address: SocketAddr) -> std::net::TcpStream {
        use std::io::Write;

        let mut stream = connect(address);
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut wire = H2_PREFACE.to_vec();
        hj_h2::frame::write_settings(&mut wire, &[]);
        stream.write_all(&wire).unwrap();
        stream
    }

    #[test]
    fn gated_h2c_upload_is_redirected_from_its_head_before_any_data() {
        use std::io::Write;

        let (_tokio_runtime, core) = mtls_gated_core();
        let address = serve_h2c_once_from(core, Some(SocketAddr::from(DIRECT_PEER)));
        let mut stream = h2c_client(address);
        let mut encoder = hj_h2::hpack::Encoder::new();
        let mut decoder = hj_h2::hpack::Decoder::new(4096, 1 << 20);
        let mut wire = Vec::new();
        h2c_upload_head(&mut encoder, &mut wire, 1, "gated.test");
        hj_h2::frame::write_frame(&mut wire, hj_h2::frame::kind::PING, 0, 0, &[1; 8]);
        stream.write_all(&wire).unwrap();
        let frames = h2c_frames_until_ping_ack(&mut stream, &mut decoder, 1);
        let kinds: Vec<u8> = frames.iter().map(|f| f.0).collect();
        assert_eq!(
            kinds,
            [hj_h2::frame::kind::HEADERS, hj_h2::frame::kind::RST_STREAM],
            "one final HEADERS (no 100 Continue, no DATA), then the reset: {frames:?}"
        );
        let (_, flags, fields, _) = &frames[0];
        assert_ne!(flags & hj_h2::frame::flags::END_STREAM, 0);
        let field = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(field(":status"), Some("301"));
        assert_eq!(field("location"), Some("https://gated.test/upload-len"));
        assert_eq!(field("content-length"), Some("0"));
        assert_eq!(field("cache-control"), Some("private, no-store"));
        assert_eq!(field("content-type"), None, "the redirect is bodiless");
        assert_eq!(
            u32::from_be_bytes(frames[1].3[..4].try_into().unwrap()),
            hj_h2::frame::error_code::NO_ERROR
        );

        // The withheld body is ignored and the connection still serves an ungated upload.
        let mut wire = Vec::new();
        hj_h2::frame::write_frame(
            &mut wire,
            hj_h2::frame::kind::DATA,
            hj_h2::frame::flags::END_STREAM,
            1,
            b"hello",
        );
        h2c_upload_head(&mut encoder, &mut wire, 3, "open.test");
        hj_h2::frame::write_frame(
            &mut wire,
            hj_h2::frame::kind::DATA,
            hj_h2::frame::flags::END_STREAM,
            3,
            b"hello",
        );
        stream.write_all(&wire).unwrap();
        let mut body = Vec::new();
        let mut status = None;
        while body != b"5" {
            let mut wire = Vec::new();
            hj_h2::frame::write_frame(&mut wire, hj_h2::frame::kind::PING, 0, 0, &[2; 8]);
            stream.write_all(&wire).unwrap();
            for (kind, _, fields, payload) in
                h2c_frames_until_ping_ack(&mut stream, &mut decoder, 3)
            {
                if let Some((_, v)) = fields.iter().find(|(n, _)| n == ":status")
                    && v != "100"
                {
                    status = Some(v.clone());
                }
                if kind == hj_h2::frame::kind::DATA {
                    body.extend_from_slice(&payload);
                }
            }
        }
        assert_eq!(status.as_deref(), Some("200"));
    }

    #[test]
    fn exempt_or_ungated_h2c_uploads_still_get_100_continue_and_dispatch() {
        use std::io::Write;

        for (host, peer) in [
            ("gated.test", None),
            ("open.test", Some(SocketAddr::from(DIRECT_PEER))),
        ] {
            let (_tokio_runtime, core) = mtls_gated_core();
            let address = serve_h2c_once_from(core, peer);
            let mut stream = h2c_client(address);
            let mut encoder = hj_h2::hpack::Encoder::new();
            let mut decoder = hj_h2::hpack::Decoder::new(4096, 1 << 20);
            let mut wire = Vec::new();
            h2c_upload_head(&mut encoder, &mut wire, 1, host);
            hj_h2::frame::write_frame(&mut wire, hj_h2::frame::kind::PING, 0, 0, &[1; 8]);
            stream.write_all(&wire).unwrap();
            let frames = h2c_frames_until_ping_ack(&mut stream, &mut decoder, 1);
            assert_eq!(frames.len(), 1, "{host}: {frames:?}");
            assert_eq!(
                frames[0]
                    .2
                    .iter()
                    .find(|(n, _)| n == ":status")
                    .map(|f| f.1.as_str()),
                Some("100"),
                "{host}"
            );
            let mut wire = Vec::new();
            hj_h2::frame::write_frame(
                &mut wire,
                hj_h2::frame::kind::DATA,
                hj_h2::frame::flags::END_STREAM,
                1,
                b"hello",
            );
            stream.write_all(&wire).unwrap();
            let mut body = Vec::new();
            let mut status = None;
            while body != b"5" {
                let mut wire = Vec::new();
                hj_h2::frame::write_frame(&mut wire, hj_h2::frame::kind::PING, 0, 0, &[2; 8]);
                stream.write_all(&wire).unwrap();
                for (kind, _, fields, payload) in
                    h2c_frames_until_ping_ack(&mut stream, &mut decoder, 1)
                {
                    if let Some((_, v)) = fields.iter().find(|(n, _)| n == ":status") {
                        status = Some(v.clone());
                    }
                    if kind == hj_h2::frame::kind::DATA {
                        body.extend_from_slice(&payload);
                    }
                }
            }
            assert_eq!(status.as_deref(), Some("200"), "{host}");
        }
    }
}

/// (Tier 2) Serve HTTP over a unix domain socket: the SAME per-connection
/// pipeline as the TCP plain path on a `monoio::net::UnixStream`, with a
/// fabricated loopback peer (the socket file's mode/owner is the real access
/// boundary). AF_UNIX has no SO_REUSEPORT, so the listener runs on ONE core —
/// sized for the few on-box peers a UDS listener serves.
/// Returns a prepared group; call `activate` to begin accepting requests.
pub(crate) enum UdsListenerInput {
    Inherited(std::os::unix::net::UnixListener),
    Handoff(worker_group::PreparedUdsHandoff),
}

pub(crate) fn spawn_uring_uds(
    holder: impl Into<ServingView>,
    listener_name: Arc<str>,
    path: std::path::PathBuf,
    input: Option<UdsListenerInput>,
    admission: bridge::BridgeAdmission,
) -> anyhow::Result<WorkerGroup> {
    let holder = holder.into();
    let shutdown = holder.load().shutdown.clone();
    let bridge = build_pipeline_bridge(holder.clone(), listener_name.clone(), admission);
    let core = CoreHandler {
        bridge,
        holder,
        listener_name,
    };
    let (listener, path_owner, predecessor) = match input {
        Some(UdsListenerInput::Inherited(listener)) => (listener, None, None),
        Some(UdsListenerInput::Handoff(prepared)) => {
            let (listener, predecessor, owner) = prepared.into_parts();
            (listener, owner, Some(predecessor))
        }
        None => {
            let (listener, owner) = unix_path::OwnedUnixPath::bind(&path)?;
            (listener, Some(Arc::new(owner)), None)
        }
    };
    listener.set_nonblocking(true)?;
    let listener = Arc::new(listener);
    let thread_listener = listener.try_clone()?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut group = WorkerGroup::for_uds_epoch(&shutdown, core.holder.trust_epoch(), path.clone());
    let retirement = group.register_uds_acceptor(listener, path_owner)?;
    if let Some(predecessor) = predecessor {
        group.follow_uds_acceptor(predecessor)?;
    }
    let activation = group.activation_gate();
    group.spawn(
        std::thread::Builder::new()
            .name("hj-uring-uds".into())
            .stack_size(crate::RUNTIME_THREAD_STACK_BYTES),
        move |shutdown| {
            maybe_pin_core_thread(0, 1);
            per_core_uds(
                core,
                path,
                thread_listener,
                shutdown,
                ready_tx,
                activation,
                retirement,
            )
        },
    )?;
    wait_for_worker_readiness("UDS", 1, ready_rx)?;
    Ok(group)
}

fn per_core_uds(
    core: CoreHandler,
    path: std::path::PathBuf,
    listener: std::os::unix::net::UnixListener,
    shutdown: CancellationToken,
    ready: WorkerReadyTx,
    activation: worker_group::ActivationGate,
    mut retirement: worker_group::UdsAcceptRetirement,
) {
    let mut rt = match build_core_runtime() {
        Ok(rt) => rt,
        Err(error) => {
            let _ = ready.send(Err(format!("build monoio runtime: {error}")));
            return;
        }
    };
    rt.block_on(async move {
        let listener = match monoio::net::UnixListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => {
                retirement.cancel();
                let _ = ready.send(Err(format!("adopt unix listener: {error}")));
                return;
            }
        };
        if ready.send(Ok(())).is_err() || !activation.wait().await {
            retirement.cancel();
            return;
        }
        tracing::info!(path = %path.display(), "uring UDS listener serving (H1/h2c → real pipeline, one core)");
        accept_drain_loop_unix(listener, shutdown, core, &mut retirement).await;
    });
}

/// Single-shot accept loop for the UDS listener (no multishot accept for
/// AF_UNIX), mirroring [`accept_drain_loop`]'s drain semantics.
async fn accept_drain_loop_unix(
    listener: monoio::net::UnixListener,
    shutdown: CancellationToken,
    core: CoreHandler,
    retirement: &mut worker_group::UdsAcceptRetirement,
) {
    use std::cell::Cell;
    use std::rc::Rc;

    let inflight = Rc::new(Cell::new(0usize));
    thread_local! {
        static UDS_CHUNK_TICKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if !UDS_CHUNK_TICKER.with(|t| t.replace(true)) {
        let ticker_shutdown = shutdown.clone();
        monoio::spawn(async move {
            loop {
                monoio::select! {
                    _ = ticker_shutdown.cancelled() => break,
                    _ = crate::pipeline::access_chunk_pending() => {}
                }
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
    // A UDS peer has no address: both ends of the bridge see fabricated loopback.
    let peer = SocketAddr::from(([127, 0, 0, 1], 0));
    let local = peer;
    let serve = |stream: monoio::net::UnixStream| {
        let state = core.holder.load();
        let cap = state.server.tuning.max_connections;
        let active_conns = state.metrics.active_conns.clone();
        let Some(permit) = ConnectionPermit::try_acquire(active_conns, cap) else {
            tracing::debug!("uring UDS: connection cap reached; rejecting");
            return;
        };
        let fut = handle_conn_bridged(
            stream,
            peer,
            local,
            core.pin_connection(),
            shutdown.clone(),
            ListenerBinding::default(),
            true,
        );
        let cnt = inflight.clone();
        cnt.set(cnt.get() + 1);
        monoio::spawn(async move {
            let _permit = permit;
            fut.await;
            cnt.set(cnt.get().saturating_sub(1));
            crate::memtrim::collect_after_connection_close();
        });
    };
    loop {
        crate::memtrim::collect_if_requested_on_thread();
        let canceller = monoio::io::Canceller::new();
        let mut accept = std::pin::pin!(listener.cancelable_accept(canceller.handle()));
        monoio::select! {
            biased;
            _ = shutdown.cancelled() => {
                // Keep the accept op alive through cancellation: dropping it makes the
                // driver discard an already-completed CQE without closing its fd, and
                // that client would hang until process exit (#670). A stream accepted
                // in the race is served by this (draining) generation.
                canceller.cancel();
                if let Ok((stream, _addr)) = accept.await {
                    serve(stream);
                }
                break;
            }
            accepted = &mut accept => {
                match accepted {
                    Ok((stream, _addr)) => serve(stream),
                    Err(e) => {
                        tracing::debug!(error = %e, "uring UDS accept failed");
                        accept_error_backoff(&e).await;
                    }
                }
            }
        }
    }
    // Release the successor as soon as this accept loop is quiescent; existing
    // connections drain independently on the retiring generation.
    retirement.cancel();
    let start = std::time::Instant::now();
    while inflight.get() > 0 && start.elapsed() < URING_DRAIN_GRACE {
        monoio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if inflight.get() > 0 {
        tracing::warn!(
            remaining = inflight.get(),
            "uring UDS: drain grace elapsed; abandoning in-flight connections"
        );
    }
    crate::pipeline::flush_access_chunks();
}

#[cfg(test)]
mod uds_tests {
    use super::*;

    /// Full stack over a REAL unix socket: spawn_uring_uds against a temp
    /// docroot, then dial it with a std client over H1 and h2c prior
    /// knowledge. The access log must render the fabricated peer as `unix:`.
    #[test]
    fn uds_listener_serves_h1_and_h2c_with_unix_peer() {
        uds_listener_lifecycle(false, true);
    }

    #[test]
    fn inherited_uds_listener_retirement_preserves_manager_path() {
        uds_listener_lifecycle(true, true);
    }

    #[test]
    fn prepared_uds_rollback_never_serves_and_removes_owned_path() {
        uds_listener_lifecycle(false, false);
    }

    #[test]
    fn prepared_inherited_uds_rollback_preserves_manager_path() {
        uds_listener_lifecycle(true, false);
    }

    fn uds_listener_lifecycle(inherit: bool, activate: bool) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = std::env::temp_dir().join(format!(
            "hj-uds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let doc_root = dir.join("html");
        std::fs::create_dir_all(&doc_root).unwrap();
        std::fs::write(doc_root.join("index.html"), b"<html>uds ok</html>").unwrap();
        let sock_path = dir.join("http.sock");
        let inherited =
            inherit.then(|| std::os::unix::net::UnixListener::bind(&sock_path).unwrap());

        // Minimal real ServerState (mirror of the e2e/smoke constructions).
        let mut by_suffix = std::collections::BTreeMap::new();
        by_suffix.insert("html".to_string(), "text/html".to_string());
        let server = hj_core::config::ServerConfig {
            server_root: dir.clone(),
            server_name: "uds-test".into(),
            user: "nobody".into(),
            group: "nobody".into(),
            index_files: vec!["index.html".into()],
            tuning: Default::default(),
            quic_enable: false,
            use_ip_in_proxy_header: 0,
            expires: Default::default(),
            cache: Default::default(),
            security: Default::default(),
            suexec: Default::default(),
            ext_processors: vec![],
            php_config: None,
            listeners: vec![hj_core::config::Listener {
                name: "uds-test".into(),
                address: "127.0.0.1:0".into(),
                secure: false,
                vhost_map: vec![hj_core::config::VhostMap {
                    vhost: "testvh".into(),
                    domains: vec!["*".into()],
                }],
                uds_path: None,
                proxy_protocol: false,
                proxy_protocol_peers: vec![],
                tls: None,
            }],
            vhosts: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "testvh".to_string(),
                    hj_core::config::VHostDecl {
                        name: "testvh".into(),
                        vh_root: doc_root.clone(),
                        config_file: std::path::PathBuf::new(),
                        allow_symbol_link: Some(true),
                        restrained: false,
                        enable_script: true,
                        config: Some(Arc::new(hj_core::config::VHostConfig {
                            doc_root: doc_root.clone(),
                            index_files: vec!["index.html".into()],
                            ..Default::default()
                        })),
                    },
                );
                m
            },
            vhost_order: vec!["testvh".into()],
            mime: hj_core::config::MimeMap {
                by_suffix,
                default_type: None,
            },
        };
        // The logger + bridge spawn on the CURRENT tokio runtime; keep the
        // runtime alive for the whole test (client I/O below is sync).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let workers = rt.block_on(async {
            let state = crate::state::ServerState::new(
                Arc::new(server),
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
            .expect("test state builds");
            let holder = Arc::new(arc_swap::ArcSwap::from(state));
            let admission = pipeline_admission(holder.clone());
            spawn_uring_uds(
                holder.clone(),
                Arc::from("uds-test"),
                sock_path.clone(),
                inherited.map(UdsListenerInput::Inherited),
                admission,
            )
            .expect("UDS listener spawns")
        });

        // Wait for the socket file, then serve an H1 request.
        for _ in 0..100 {
            if sock_path.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut client = std::os::unix::net::UnixStream::connect(&sock_path).unwrap();
        client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: uds.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let mut probe = [0u8; 1];
        let error = client
            .read(&mut probe)
            .expect_err("prepared listener must not respond");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        if !activate {
            drop(workers);
            match client.read(&mut probe) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("rolled-back listener retained queued connection: {other:?}"),
            }
            assert_eq!(sock_path.exists(), inherit);
            drop(client);
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
        workers.activate();
        let mut buf = String::new();
        let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = client.read_to_string(&mut buf);
        assert!(buf.starts_with("HTTP/1.1 200 OK"), "got {buf:.80}");
        assert!(buf.contains("uds ok"), "body served over UDS: {buf:.120}");

        let h1 = |raw: &[u8]| {
            let mut client = std::os::unix::net::UnixStream::connect(&sock_path).unwrap();
            client.write_all(raw).unwrap();
            let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = String::new();
            let _ = client.read_to_string(&mut buf);
            buf
        };
        let bare_lf = h1(b"GET /index.html HTTP/1.1\nHost: uds.test\nConnection: close\n\n");
        assert!(
            bare_lf.starts_with("HTTP/1.1 400"),
            "bare LF: {bare_lf:.80}"
        );
        let connect = h1(b"CONNECT uds.test:443 HTTP/1.1\r\nHost: uds.test:443\r\n\r\n");
        assert!(
            connect.starts_with("HTTP/1.1 405"),
            "CONNECT: {connect:.80}"
        );
        let hostless = h1(b"GET /index.html HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert!(
            hostless.starts_with("HTTP/1.1 400"),
            "no Host: {hostless:.80}"
        );
        let absolute = h1(
            b"GET http://uds.test/index.html HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
        );
        assert!(
            absolute.starts_with("HTTP/1.1 200 OK"),
            "absolute-form: {absolute:.80}"
        );

        // h2c prior knowledge must reach the same pipeline (a SETTINGS-only
        // preface gets an h2 SETTINGS reply, not an H1 error).
        let mut client = std::os::unix::net::UnixStream::connect(&sock_path).unwrap();
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 9];
        let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        // The h2 server replies with a SETTINGS frame: len/type/flags = 0/4/0.
        match client.read_exact(&mut buf) {
            Ok(_) => {}
            Err(e) => panic!("h2c prior knowledge over UDS got no SETTINGS reply: {e}"),
        }
        let _ = AtomicU64::new(0).load(Ordering::Relaxed);

        drop(client);
        drop(workers);
        assert!(std::os::unix::net::UnixStream::connect(&sock_path).is_err());
        assert_eq!(
            sock_path.exists(),
            inherit,
            "only self-owned paths are removed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
