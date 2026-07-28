//! # hj-lsapi — native LSAPI client + lsphp supervisor
//!
//! A from-scratch, async implementation of LiteSpeed's LSAPI protocol used to
//! talk to `lsphp` (PHP) workers, plus a supervisor that spawns and manages an
//! lsphp worker pool. This is the httpjet replacement for LiteSpeed's built-in
//! PHP/LSAPI handling.
//!
//! The wire format is transcribed from the upstream PHP `litespeed` SAPI sources,
//! vendored under `vendor/` (`lsapidef.h`, `lsapilib.c`; BSD-3-Clause, © Lite
//! Speed Technologies / The PHP Group). See [`proto`] for the full CONSTANTS
//! documentation (packet header layout, endianness flag, packet types, env-table
//! and RESP_HEADER encodings, and the fd-0 listen-socket handoff).
//!
//! ## What the orchestrator wires up
//!
//! - [`LsapiCodec`] — `tokio_util` `Encoder<LsapiFrame>` + `Decoder` for the
//!   8-byte-header wire format (honors the endianness flag on decode).
//! - [`LsapiFrame`] / [`PacketType`] — raw frames and type constants;
//!   [`build_begin_request_body`] assembles a BEGIN_REQUEST body (req header +
//!   CGI env table + request body), and [`RespHeader`] / [`parse_resp_header`]
//!   parse RESP_HEADER packets.
//! - [`build_cgi_env`] / [`CgiEnvBuilder`] — produce the CGI/1.1 environment.
//! - [`LsapiPool`] — bounded pool of UDS connections with `acquire()` honoring
//!   an init timeout.
//! - [`LsphpSupervisor`] — binds a listen socket, hands it to a spawned `lsphp`
//!   on fd 0, sets LSAPI env, drops privileges when root; `start`/`drain`/
//!   `restart`/`is_alive`.
//! - [`Lsapi`] — the [`hj_core::Handler`] that dispatches a request to lsphp and
//!   streams the response back unbuffered (`respBuffer = 0`), routing STDERR to
//!   `tracing` and sending ABORT on client disconnect.
//!
//! ## Typical integration
//!
//! ```no_run
//! # use std::sync::Arc;
//! use hj_lsapi::{Lsapi, LsapiPool, LsphpSupervisor, SupervisorConfig};
//!
//! # async fn wire(php: &hj_core::config::PhpConfig) -> std::io::Result<()> {
//! // R&D: use a SEPARATE socket path, never the prod php8.sock.
//! let sock = "/tmp/php8-httpjet.sock";
//! let sup = LsphpSupervisor::new(SupervisorConfig::from_php_config(
//!     php, sock, "nobody", "nobody",
//! ));
//! sup.start().await?;
//!
//! let pool = Arc::new(LsapiPool::new(sock, php.max_conns, php.init_timeout));
//! let handler = Arc::new(Lsapi::new(pool));
//! // register `handler` for the PHP script handlers / contexts...
//! # let _ = handler;
//! # Ok(())
//! # }
//! ```

pub mod cgi;
pub mod handler;
pub mod jail;
pub mod limits;
pub mod monitor;
pub mod pool;
pub mod proto;
pub mod registry;
pub mod supervisor;

pub use cgi::{CgiEnvBuilder, build_cgi_env};
pub use handler::{Lsapi, LsapiRetryInfo, LsapiScript, LsapiTiming};
pub use jail::{Credentials, JailConfig, NamespaceFlags};
pub use limits::ResourceLimits;
pub use monitor::{InFlight, InFlightGuard, Monitor, MonitorConfig};
pub use pool::{
    DEFAULT_EXTERNAL_GENERATION_PATH, ExternalGeneration, ExternalGenerationWriter, LsapiPool,
    PoolError, PoolStats, PooledConn, ReturnGuard,
};
pub use proto::{
    HEADER_INDEX_LEN, HEADER_OFFSET_LEN, KNOWN_HEADER_COUNT, KNOWN_HEADER_NAMES, LsapiCodec,
    LsapiFrame, MAX_DATA_PACKET_LEN, PACKET_HEADER_LEN, PacketType, REQ_HEADER_LEN, RespHeader,
    SOCK_FILENO, SpecialEnvType, build_begin_request, build_begin_request_body,
    build_begin_request_framed, known_header_index, parse_resp_header,
};
pub use registry::{LsapiRegistry, PoolKey};
pub use supervisor::{LsphpSupervisor, PromotionHook, SocketSource, SupervisorConfig, WorkerState};
