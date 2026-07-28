//! Socket activation (systemd) for the lsphp pool: when the supervisor is given an
//! inherited listen fd (`with_listen_fd`), it must adopt that PERSISTENT socket — never
//! bind, never unlink — so the socket survives a restart and a client dialing during the
//! swap is not refused. These guard the ECONNREFUSED-burst fix at the supervisor layer.
//!
//! `#[ignore]`: spawns a process + binds a socket; run manually on an R&D box.

use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use hj_lsapi::{LsphpSupervisor, SocketSource, SupervisorConfig};

mod common;

/// A trivial worker that accepts the supervisor's application-level LSAPI probe
/// and exits cleanly on SIGUSR1 (the default).
fn write_sleep_worker() -> PathBuf {
    common::write_accepting_worker("sa", false)
}

fn live_socket_backlog(path: &std::path::Path) -> u32 {
    let output = Command::new("ss")
        .args(["-xlH"])
        .output()
        .expect("ss must inspect the live Unix listener");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find(|line| {
            line.split_whitespace()
                .any(|field| field == path.as_os_str())
        })
        .and_then(|line| line.split_whitespace().nth(3))
        .and_then(|value| value.parse().ok())
        .expect("live listener Send-Q/backlog")
}

fn php_config(command: PathBuf) -> hj_core::config::PhpConfig {
    hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command,
        suffixes: vec!["php".into()],
        env: vec![],
        max_conns: 2,
        init_timeout: Duration::from_secs(5),
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

#[tokio::test]
#[ignore = "spawns a process + binds a socket; run manually on an R&D box"]
async fn inherited_fd_socket_survives_restart_and_is_never_unlinked() {
    let worker = write_sleep_worker();
    let sock = std::env::temp_dir().join(format!("php8-hj-sa-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    // Stand in for systemd: WE create + own the listening socket, then hand its fd to the
    // supervisor. From the supervisor's view this is identical to a socket-activation fd.
    let listener = StdUnixListener::bind(&sock).unwrap();
    rustix::net::listen(&listener, 7).unwrap();
    assert_eq!(live_socket_backlog(&sock), 7);
    let fd: OwnedFd = listener.into();
    let inode0 = std::fs::metadata(&sock).unwrap().ino();

    let cfg = SupervisorConfig::from_php_config(&php_config(worker.clone()), &sock, "", "");
    let sup = Arc::new(LsphpSupervisor::new(cfg).with_listen_fd(fd));
    assert_eq!(sup.config().socket_source, SocketSource::Inherited);

    // start() must adopt (dup) the held fd — NOT remove_file + rebind. Same inode after.
    sup.start()
        .await
        .expect("worker should come up on the inherited socket");
    assert_eq!(
        live_socket_backlog(&sock),
        1024,
        "inherited adoption must resize an already-active listener with listen(2)"
    );
    let inode1 = std::fs::metadata(&sock).unwrap().ino();
    assert_eq!(
        inode0, inode1,
        "start() must not rebind the inherited socket (inode changed)"
    );

    // A restart (drain + start) must keep the SAME socket — the held fd is re-dup'd, never
    // unlinked/rebound. This is the property that eliminates the ECONNREFUSED window.
    sup.kill_and_restart()
        .await
        .expect("restart should reuse the held fd");
    let inode2 = std::fs::metadata(&sock).unwrap().ino();
    assert_eq!(
        inode0, inode2,
        "restart must not unlink/rebind the inherited socket"
    );

    // The graceful shutdown drain must ALSO leave the socket file in place (systemd owns it).
    sup.drain_graceful().await.expect("drain ok");
    assert!(
        sock.exists(),
        "drain must not unlink a systemd-owned socket"
    );

    // Cleanup (we are the socket owner in this test).
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&worker);
}
