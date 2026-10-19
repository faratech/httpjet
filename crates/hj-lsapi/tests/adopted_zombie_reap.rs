use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use hj_core::config::PhpConfig;
use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

const HELPER_ENV: &str = "HJ_ADOPTED_ZOMBIE_REAP_HELPER";

/// Subreaper mode is process-wide, so each scenario runs in its own copy of
/// this test binary.
fn run_isolated(test: &str, helper: fn()) {
    if std::env::var_os(HELPER_ENV).is_some() {
        helper();
        return;
    }
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(HELPER_ENV, "1")
        .status()
        .expect("spawn isolated subreaper test");
    assert!(status.success(), "isolated subreaper test {test} failed");
}

#[test]
fn adopted_request_subprocess_zombies_are_reaped() {
    run_isolated("adopted_request_subprocess_zombies_are_reaped", reap_helper);
}

#[test]
fn registered_child_exit_status_is_never_consumed() {
    run_isolated(
        "registered_child_exit_status_is_never_consumed",
        registered_child_helper,
    );
}

fn supervisor() -> LsphpSupervisor {
    LsphpSupervisor::new(SupervisorConfig::from_php_config(
        &PhpConfig::default(),
        "/tmp/hj-adopted-zombie-reap.sock",
        "",
        "",
    ))
}

fn reap_helper() {
    let supervisor = supervisor();

    // The process shapes PHP's background exec()s leave behind: the shell exits
    // first, its background job is adopted by the subreaper, and exits later.
    let adopted: Vec<u32> = [
        "curl --version >/dev/null 2>&1 & echo $!",
        "sleep 0 >/dev/null 2>&1 & echo $!",
        "(true; true) >/dev/null 2>&1 & echo $!",
    ]
    .into_iter()
    .map(spawn_detached_in_worker_session)
    .collect();
    for &pid in &adopted {
        wait_for_zombie(pid);
    }

    // A child this process forked and still waits on stays in our session; the
    // pass must leave its exit status alone.
    let mut direct = Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .spawn()
        .expect("spawn direct child");
    wait_for_zombie(direct.id());

    supervisor.poll_liveness();
    for pid in adopted {
        assert_eq!(
            proc_state(pid),
            None,
            "the monitor pass must reap adopted pid {pid}"
        );
    }
    assert_eq!(
        direct.wait().expect("direct child still waitable").code(),
        Some(3)
    );
}

fn registered_child_helper() {
    let supervisor = supervisor();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "exit 7"]);
        // A new session, so only the owned-child registry can protect it.
        // SAFETY: setsid is async-signal-safe and touches no parent state.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child =
            hj_lsapi::supervisor::spawn_owned_child(&mut command).expect("spawn owned child");
        let pid = child.id().expect("pid");
        wait_for_zombie(pid);

        supervisor.poll_liveness();
        assert_eq!(
            proc_state(pid),
            Some(b'Z'),
            "an owned child must not be reaped"
        );
        let status = child.wait().await.expect("owner keeps the exit status");
        assert_eq!(status.code(), Some(7));
    });
}

/// Runs `script` in a new session, as every lsphp worker does after `setsid`,
/// and returns the pid of the background job it leaves behind.
fn spawn_detached_in_worker_session(script: &str) -> u32 {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", script]);
    // SAFETY: setsid is async-signal-safe and touches no parent state.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let output = command.output().expect("spawn detached request helper");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("pid output is utf8")
        .trim()
        .parse()
        .expect("pid output is numeric")
}

fn wait_for_zombie(pid: u32) {
    for _ in 0..200 {
        if proc_state(pid) == Some(b'Z') {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("pid {pid} must become a zombie before the monitor pass");
}

fn proc_state(pid: u32) -> Option<u8> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1.trim_start();
    tail.as_bytes().first().copied()
}
