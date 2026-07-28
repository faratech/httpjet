//! (#29) A shutdown cancellation must cut short the grace wait inside
//! `drain()` (reached via `kill_and_restart`), so the monitor ticker is not
//! pinned for the full grace window during `systemctl stop`.
//!
//! We run a worker that IGNORES SIGTERM (so `drain()` would otherwise wait out
//! its whole grace window), fire the supervisor's cancellation token mid-drain,
//! and assert `kill_and_restart()` returns far sooner than the grace window. The
//! child is reaped via SIGKILL (which cannot be trapped), so no process leaks.
//!
//! Uses a tiny `/bin/sh` worker as the "ignores SIGTERM" stand-in (real lsphp
//! exits cleanly on SIGTERM, so it cannot exercise the slow path). Marked
//! `#[ignore]` because it spawns a process + binds a socket.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

mod common;

/// Write an executable worker that answers the application-level LSAPI readiness
/// probe, then ignores SIGTERM and keeps accepting.
fn write_sigterm_ignoring_worker() -> PathBuf {
    common::write_accepting_worker("sigign", true)
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
async fn kill_and_restart_aborts_grace_on_cancel() {
    let worker = write_sigterm_ignoring_worker();
    let sock = std::env::temp_dir().join(format!("php8-hj-cancel-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    let cfg = SupervisorConfig::from_php_config(&php_config(worker.clone()), &sock, "", "");
    let sup = std::sync::Arc::new(LsphpSupervisor::new(cfg));
    sup.start()
        .await
        .expect("worker should accept the LSAPI readiness probe");

    let cancel = sup.cancel_token();

    // Fire the cancellation shortly after the kill starts, so the grace wait is
    // interrupted mid-flight rather than never entered.
    let canceller = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        })
    };

    let started = Instant::now();
    // kill_and_restart -> drain() (cancellable grace) -> start(). With the worker
    // ignoring SIGTERM, an UNcancellable drain would block the full 20s grace.
    let _ = sup.kill_and_restart().await;
    let elapsed = started.elapsed();
    canceller.await.unwrap();

    assert!(
        elapsed < Duration::from_secs(10),
        "kill_and_restart should return well under the grace window once cancelled, took {elapsed:?}"
    );

    // Clean up: the token stays cancelled, so this drain also returns promptly,
    // and start_kill() SIGKILLs the (trap-immune-to-TERM) child.
    let _ = sup.drain().await;
    if let Some(pid) = sup.worker_pid() {
        if let Some(pid) = rustix_pid(pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&worker);
}

fn rustix_pid(raw: u32) -> Option<rustix::process::Pid> {
    rustix::process::Pid::from_raw(raw as i32)
}
