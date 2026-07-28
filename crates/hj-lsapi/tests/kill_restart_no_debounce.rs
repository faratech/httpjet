//! (#2) `kill_and_restart` must bypass the `min_restart_interval` debounce.
//!
//! The Tier-2 hung-request path SIGTERM/SIGKILLs a wedged worker and MUST then
//! respawn one immediately. The old code called `restart_debounced`, which —
//! when a restart had just happened (`last_restart` recent) — silently returned
//! `Ok(())` without spawning, leaving PHP dead until the 10s window expired.
//!
//! This test drives a recent restart (so `last_restart` is fresh and well inside
//! the 10s `min_restart_interval`), then calls `kill_and_restart()` and asserts a
//! NEW worker came up right away (generation advanced, state `Good`, a live PID,
//! socket accepts) — i.e. the debounce did NOT block the respawn.
//!
//! Spawns the real lsphp, so it is `#[ignore]` (run via `cargo test -- --ignored`
//! on an R&D box). Skips cleanly if the binary is absent.

use std::path::PathBuf;
use std::time::Duration;

use hj_lsapi::{LsphpSupervisor, SupervisorConfig, WorkerState};

fn php_config(lsphp: PathBuf) -> hj_core::config::PhpConfig {
    hj_core::config::PhpConfig {
        handler_id: "lsphp".into(),
        command: lsphp,
        suffixes: vec!["php".into()],
        env: vec![("PHP_LSAPI_CHILDREN".into(), "2".into())],
        max_conns: 2,
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
        // A LONG debounce: under the old code this would block the forceful
        // respawn after a fresh restart. The fix must ignore it.
        min_restart_interval: Duration::from_secs(10),
        max_restart_backoff: Duration::from_secs(30),
    }
}

#[tokio::test]
#[ignore = "spawns the real lsphp; run manually on an R&D box"]
async fn kill_and_restart_ignores_debounce() {
    let lsphp = PathBuf::from("/usr/local/lsws/lsphp8/bin/lsphp");
    if !lsphp.exists() {
        eprintln!("lsphp not found at {lsphp:?}; skipping");
        return;
    }

    let sock =
        std::env::temp_dir().join(format!("php8-hj-killdebounce-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    let cfg = SupervisorConfig::from_php_config(&php_config(lsphp), &sock, "", "");
    let sup = LsphpSupervisor::new(cfg);

    sup.start().await.expect("initial lsphp start");
    assert_eq!(sup.state(), WorkerState::Good);

    // Force `last_restart = now` by performing a real debounced restart first
    // (the initial last_restart is ~1h in the past, so this one is allowed and
    // stamps the window). After this, we are firmly INSIDE the 10s debounce.
    sup.restart_debounced().await.expect("priming restart");
    assert_eq!(sup.state(), WorkerState::Good);
    let gen_before = sup.generation();
    let pid_before = sup.worker_pid().expect("a live worker before the kill");

    // The forceful path: it MUST replace the worker now, despite the fresh
    // last_restart that would otherwise debounce restart_debounced() to a no-op.
    sup.kill_and_restart()
        .await
        .expect("kill_and_restart should respawn immediately");

    assert_eq!(
        sup.state(),
        WorkerState::Good,
        "a fresh worker must be Good, not left dead"
    );
    assert!(
        sup.worker_pid().is_some(),
        "g.child must hold a new live worker"
    );
    assert!(
        sup.generation() > gen_before,
        "generation must advance (new worker spawned), not stay at {gen_before}"
    );
    assert_ne!(
        sup.worker_pid(),
        Some(pid_before),
        "the wedged worker pid must have been replaced"
    );
    assert!(
        sup.is_alive().unwrap(),
        "the replacement master must still be alive after readiness"
    );

    // The new worker's socket actually accepts.
    tokio::net::UnixStream::connect(&sock)
        .await
        .expect("new lsphp socket should accept connections");

    sup.drain().await.unwrap();
    let _ = std::fs::remove_file(&sock);
}
