//! (#29 regression) The FINAL shutdown drain must HONOR the SIGTERM→grace window even
//! though the shutdown token is already fired (registry `drain_all` fires it to stop the
//! monitor ticker). `drain_graceful()` must NOT short-circuit to immediate SIGKILL the way
//! the abortable `drain()` does — otherwise every worker is killed instantly at shutdown,
//! dropping in-flight requests.
//!
//! A SIGTERM-ignoring worker stands in for "still finishing in-flight work": with the
//! token fired, abortable `drain()` returns at once (covered by kill_cancel_responsive.rs),
//! while `drain_graceful()` keeps waiting its grace (it would run to the full GRACE_TIMEOUT).
//!
//! `#[ignore]`: spawns a process + binds a socket; run manually on an R&D box.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

mod common;

fn write_sigterm_ignoring_worker() -> PathBuf {
    common::write_accepting_worker("grace", true)
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

fn rustix_pid(raw: u32) -> Option<rustix::process::Pid> {
    rustix::process::Pid::from_raw(raw as i32)
}

#[tokio::test]
#[ignore = "spawns a process + binds a socket; run manually on an R&D box"]
async fn drain_graceful_honors_grace_despite_fired_token() {
    let worker = write_sigterm_ignoring_worker();
    let sock = std::env::temp_dir().join(format!("php8-hj-grace-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    let cfg = SupervisorConfig::from_php_config(&php_config(worker.clone()), &sock, "", "");
    let sup = Arc::new(LsphpSupervisor::new(cfg));
    sup.start()
        .await
        .expect("worker should accept the LSAPI readiness probe");

    // Capture the PID before drain takes the child, so we can reap the leaked (SIGTERM-immune)
    // worker after we cut drain_graceful off below.
    let pid = sup.worker_pid();

    // Simulate shutdown: fire the token exactly as registry drain_all does to stop the ticker.
    sup.cancel_token().cancel();

    // drain_graceful() must IGNORE the fired token and keep waiting the grace window (the
    // worker ignores SIGTERM, so it would run to the full GRACE_TIMEOUT before SIGKILL). It
    // must therefore NOT have returned within a few seconds. The abortable drain() would
    // return immediately here — that is the regression this guards.
    let r = tokio::time::timeout(Duration::from_secs(3), sup.drain_graceful()).await;
    assert!(
        r.is_err(),
        "drain_graceful must honor the grace window even with the shutdown token fired \
         (it returned early — the #29 immediate-SIGKILL regression)"
    );

    // Cleanup: SIGKILL the still-alive worker (our timeout cut drain_graceful off mid-grace).
    if let Some(raw) = pid {
        if let Some(p) = rustix_pid(raw) {
            let _ = rustix::process::kill_process(p, rustix::process::Signal::KILL);
        }
    }
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&worker);
}
