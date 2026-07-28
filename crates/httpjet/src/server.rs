//! Listening-socket adoption for the io_uring transport.
//!
//! The process runs as `nobody` and cannot self-bind privileged `:80`/`:443`, so in
//! production systemd socket activation (`httpjet.socket`) binds the sockets as root and
//! passes them as inherited fds; [`listeners_from_env`] adopts them. The accept loops
//! themselves live in [`crate::uring`] (one pinned-core monoio io_uring runtime per
//! inherited `SO_REUSEPORT` socket); this module only adopts the inherited sockets and
//! hands them on. Alt-port / manual runs (no socket activation) self-bind inside `uring`.

use std::io;
use std::os::fd::FromRawFd;

use socket2::{Socket, Type};
use tokio::net::TcpListener;

pub(crate) fn set_cloexec(fd: &impl std::os::fd::AsFd) -> io::Result<()> {
    let flags =
        rustix::io::fcntl_getfd(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// (OPS8) Listening sockets inherited from systemd socket activation
/// (`httpjet.socket`), grouped by role. systemd owns these fds and holds them
/// open ACROSS a `systemctl restart httpjet.service`, so the accept queue is
/// never closed during a binary deploy — no backlog/new-connection RST. Each
/// `Vec` holds one socket per worker (the `.socket` unit lists each
/// `ListenStream`/`ListenDatagram` N× with `ReusePort=yes`, reproducing the
/// per-worker `SO_REUSEPORT` fan-out the io_uring cores adopt).
pub struct InheritedListeners {
    pub http: Vec<TcpListener>,
    pub https: Vec<TcpListener>,
    pub quic: Vec<std::net::UdpSocket>,
}

/// Adopt sockets passed by systemd socket activation (`sd_listen_fds`). Returns
/// `Ok(None)` when not socket-activated (no `LISTEN_FDS`) — the caller then
/// self-binds (alt-port test instances are unaffected). Classifies each inherited
/// fd by introspection (`getsockname`/`SO_TYPE`), NOT by `LISTEN_FDNAMES` (systemd
/// collapses duplicate names), so fd order does not matter. Does NOT re-bind/re-listen.
/// Must be called within the tokio runtime (`TcpListener::from_std`); the io_uring cores
/// convert each adopted listener back to `std` (`into_std`) and re-adopt it on their core.
pub fn listeners_from_env(
    http_port: u16,
    https_port: u16,
) -> io::Result<Option<InheritedListeners>> {
    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok());
    let (Some(pid), Some(n)) = (listen_pid, listen_fds) else {
        return Ok(None);
    };
    // The fds are ours only if LISTEN_PID matches; otherwise they were meant for a
    // different process. This function is called once, and spawned lsphp children use
    // `env_clear`, so retaining LISTEN_* avoids unsafe process-global environment mutation.
    if pid != std::process::id() || n <= 0 {
        return Ok(None);
    }

    let mut http = Vec::new();
    let mut https = Vec::new();
    let mut quic = Vec::new();
    // systemd passes activation fds starting at SD_LISTEN_FDS_START (3).
    for fd in 3..(3 + n) {
        // SAFETY: systemd handed us this fd; we take sole ownership for the
        // process lifetime (it lives until the listener/socket is dropped).
        let sock = unsafe { Socket::from_raw_fd(fd) };
        set_cloexec(&sock)?;
        sock.set_nonblocking(true)?;
        let ty = sock.r#type()?;
        let port = sock
            .local_addr()?
            .as_socket()
            .map(|a| a.port())
            .unwrap_or(0);
        if ty == Type::STREAM && port == http_port {
            http.push(TcpListener::from_std(sock.into())?);
        } else if ty == Type::STREAM && port == https_port {
            https.push(TcpListener::from_std(sock.into())?);
        } else if ty == Type::DGRAM && port == https_port {
            quic.push(sock.into());
        } else {
            // Unrecognized socket-activation fd (wrong port/type). Dropping `sock`
            // closes it — a loud failure for a misconfigured .socket unit.
            tracing::error!(
                fd,
                ?ty,
                port,
                "socket activation: unrecognized inherited fd; closing"
            );
        }
    }
    tracing::info!(
        http = http.len(),
        https = https.len(),
        quic = quic.len(),
        "adopted systemd socket-activation fds (zero-downtime deploy: socket survives restart)"
    );
    Ok(Some(InheritedListeners { http, https, quic }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adopted_socket_is_marked_close_on_exec() {
        let socket = Socket::new(socket2::Domain::UNIX, Type::STREAM, None).unwrap();
        rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::empty()).unwrap();

        set_cloexec(&socket).unwrap();

        assert!(
            rustix::io::fcntl_getfd(&socket)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
    }
}
