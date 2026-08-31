//! Listening-socket adoption for the io_uring transport.
//!
//! The process runs as `nobody` and cannot self-bind privileged `:80`/`:443`, so in
//! production systemd socket activation (`httpjet.socket`) binds the sockets as root and
//! passes them as inherited fds; [`listeners_from_env`] adopts them. The accept loops
//! themselves live in [`crate::uring`] (one pinned-core monoio io_uring runtime per
//! inherited `SO_REUSEPORT` socket); this module only adopts the inherited sockets and
//! hands them on. Alt-port / manual runs (no socket activation) self-bind inside `uring`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};

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
    /// (Tier 2) socket-activated unix listener(s) matching the configured UDS path.
    pub unix: Vec<std::os::unix::net::UnixListener>,
}

/// Adopt sockets passed by systemd socket activation (`sd_listen_fds`). Returns
/// `Ok(None)` when not socket-activated (no `LISTEN_FDS`) — the caller then
/// self-binds (alt-port test instances are unaffected). Classifies each inherited
/// fd by introspection (`getsockname`/`SO_TYPE`), NOT by `LISTEN_FDNAMES` (systemd
/// collapses duplicate names), so fd order does not matter. Does NOT re-bind/re-listen.

/// One inherited activation fd, classified by family/type/address.
enum Adopted {
    Http(tokio::net::TcpListener),
    Https(tokio::net::TcpListener),
    Quic(std::net::UdpSocket),
    Unix(std::os::unix::net::UnixListener),
    /// Nothing httpjet serves on — the caller closes the fd (loud in the logs).
    Unknown,
}

/// (Tier 2) Classify ONE socket-activated fd by family/type/address: TCP STREAM
/// by port (http/https), UDP DGRAM by port (quic), and AF_UNIX STREAM by exact
/// pathname match against the configured UDS path. Everything else is
/// `Unknown` and gets closed.
fn classify_activated(
    sock: Socket,
    http_port: u16,
    https_port: u16,
    uds_path: Option<&std::path::Path>,
) -> io::Result<Adopted> {
    let ty = sock.r#type()?;
    let local = sock.local_addr()?;
    if local.is_unix() {
        // Adopt only the EXACT configured path; an unmatched AF_UNIX fd is a
        // misconfigured .socket unit — close it rather than serve on a mystery socket.
        if ty == Type::STREAM && local.as_pathname().is_some_and(|p| Some(p) == uds_path) {
            // socket2 hands the fd over as an OwnedFd; std adopts it by value.
            let owned: std::os::fd::OwnedFd = sock.into();
            return Ok(Adopted::Unix(std::os::unix::net::UnixListener::from(owned)));
        }
        return Ok(Adopted::Unknown);
    }
    let port = local.as_socket().map(|a| a.port()).unwrap_or(0);
    if ty == Type::STREAM && port == http_port {
        return Ok(Adopted::Http(TcpListener::from_std(sock.into())?));
    }
    if ty == Type::STREAM && port == https_port {
        return Ok(Adopted::Https(TcpListener::from_std(sock.into())?));
    }
    if ty == Type::DGRAM && port == https_port {
        return Ok(Adopted::Quic(sock.into()));
    }
    Ok(Adopted::Unknown)
}

/// Must be called within the tokio runtime (`TcpListener::from_std`); the io_uring cores
/// convert each adopted listener back to `std` (`into_std`) and re-adopt it on their core.
pub fn listeners_from_env(
    http_port: u16,
    https_port: u16,
    uds_path: Option<&std::path::Path>,
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
    let mut unix = Vec::new();
    // systemd passes activation fds starting at SD_LISTEN_FDS_START (3).
    for fd in 3..(3 + n) {
        // SAFETY: systemd handed us this fd; we take sole ownership for the
        // process lifetime (it lives until the listener/socket is dropped).
        let sock = unsafe { Socket::from_raw_fd(fd) };
        set_cloexec(&sock)?;
        sock.set_nonblocking(true)?;
        match classify_activated(sock, http_port, https_port, uds_path)? {
            Adopted::Http(l) => http.push(l),
            Adopted::Https(l) => https.push(l),
            Adopted::Quic(s) => quic.push(s),
            Adopted::Unix(l) => unix.push(l),
            // Unrecognized socket-activation fd (wrong port/type). Dropping it
            // closes the fd — a loud failure for a misconfigured .socket unit.
            Adopted::Unknown => {
                tracing::error!(fd, "socket activation: unrecognized inherited fd; closing")
            }
        }
    }
    tracing::info!(
        http = http.len(),
        https = https.len(),
        quic = quic.len(),
        unix = unix.len(),
        "adopted systemd socket-activation fds (zero-downtime deploy: socket survives restart)"
    );
    Ok(Some(InheritedListeners {
        http,
        https,
        quic,
        unix,
    }))
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

#[cfg(test)]
mod classify_tests {
    use super::*;
    use socket2::{Domain, Protocol as S2Protocol};

    fn tcp(port: u16) -> Socket {
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(S2Protocol::TCP)).unwrap();
        s.bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
        s.set_nonblocking(true).unwrap();
        s.listen(8).unwrap();
        s
    }

    fn udp(port: u16) -> Socket {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(S2Protocol::UDP)).unwrap();
        s.bind(
            &format!("127.0.0.1:{port}")
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
        s.set_nonblocking(true).unwrap();
        s
    }

    fn unix(path: &std::path::Path) -> Socket {
        // Dropping a bound UnixListener does NOT unlink its file — clear any
        // leftover from an earlier bind in this test.
        let _ = std::fs::remove_file(path);
        let s = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        s.bind(&socket2::SockAddr::unix(path).unwrap()).unwrap();
        s.set_nonblocking(true).unwrap();
        s.listen(8).unwrap();
        s
    }

    fn port_of(s: &Socket) -> u16 {
        s.local_addr().unwrap().as_socket().unwrap().port()
    }

    #[tokio::test]
    async fn tcp_and_udp_fds_classify_by_port_and_type() {
        let http = tcp(0);
        let http_port = port_of(&http);
        let https = tcp(0);
        let https_port = port_of(&https);

        match classify_activated(http, http_port, https_port, None).unwrap() {
            Adopted::Http(_) => {}
            _ => panic!("a TCP stream on the http port must classify as Http"),
        }
        match classify_activated(https, http_port, https_port, None).unwrap() {
            Adopted::Https(_) => {}
            _ => panic!("a TCP stream on the https port must classify as Https"),
        }
        // A UDP socket on the https port is the QUIC listener — but a UDP fd on
        // some third port is Unknown, not a listener we serve.
        let quic = udp(https_port);
        match classify_activated(quic, http_port, https_port, None).unwrap() {
            Adopted::Quic(_) => {}
            _ => panic!("UDP on the https port must classify as Quic"),
        }
        let stray_udp = udp(0);
        let stray_port = port_of(&stray_udp);
        assert!(matches!(
            classify_activated(stray_udp, http_port, https_port, None).unwrap(),
            Adopted::Unknown
        ));
        let _ = stray_port;
    }

    #[tokio::test]
    async fn unix_fds_adopt_only_on_exact_path_match() {
        let dir = std::env::temp_dir().join(format!(
            "hj-classify-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let configured = dir.join("http.sock");
        let other = dir.join("other.sock");

        // Exact pathname match adopts.
        let mine = unix(&configured);
        match classify_activated(mine, 80, 443, Some(&configured)).unwrap() {
            Adopted::Unix(_) => {}
            _ => panic!("the configured UDS path must classify as Unix"),
        }
        // A DIFFERENT unix path is Unknown even when a UDS path is configured.
        let stranger = unix(&other);
        assert!(matches!(
            classify_activated(stranger, 80, 443, Some(&configured)).unwrap(),
            Adopted::Unknown
        ));
        // No UDS configured at all: every AF_UNIX fd is Unknown.
        let unconfigured = unix(&configured);
        assert!(matches!(
            classify_activated(unconfigured, 80, 443, None).unwrap(),
            Adopted::Unknown
        ));

        std::fs::remove_dir_all(&dir).ok();
    }
}
