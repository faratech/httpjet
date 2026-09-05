use std::net::{IpAddr, SocketAddr};

use monoio::net::{TcpListener, TcpStream};

#[cfg(unix)]
fn assert_close_on_exec(stream: &TcpStream) {
    use std::os::fd::AsRawFd;

    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    assert!(
        flags >= 0,
        "F_GETFD failed: {}",
        std::io::Error::last_os_error()
    );
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "accepted fd must be close-on-exec"
    );
}

macro_rules! test_accept {
    ($(($ident:ident, $target:expr),)*) => {
        $(
            #[monoio::test_all]
            async fn $ident() {
                let listener = TcpListener::bind($target).unwrap();
                let addr = listener.local_addr().unwrap();
                let (tx, rx) = local_sync::oneshot::channel();
                monoio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    assert!(tx.send(socket).is_ok());
                });
                let cli = TcpStream::connect(&addr).await.unwrap();
                let srv = rx.await.unwrap();
                #[cfg(unix)]
                assert_close_on_exec(&srv);
                assert_eq!(cli.local_addr().unwrap(), srv.peer_addr().unwrap());
            }
        )*
    }
}

test_accept! {
    (ip_str, "127.0.0.1:0"),
    (host_str, "localhost:0"),
    (socket_addr, "127.0.0.1:0".parse::<SocketAddr>().unwrap()),
    (str_port_tuple, ("127.0.0.1", 0)),
    (ip_port_tuple, ("127.0.0.1".parse::<IpAddr>().unwrap(), 0)),
}
