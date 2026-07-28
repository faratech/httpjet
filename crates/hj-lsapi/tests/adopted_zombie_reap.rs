use std::process::Command;
use std::time::Duration;

use hj_core::config::PhpConfig;
use hj_lsapi::{LsphpSupervisor, SupervisorConfig};

const HELPER_ENV: &str = "HJ_ADOPTED_ZOMBIE_REAP_HELPER";

#[test]
fn adopted_request_subprocess_zombies_are_reaped() {
    if std::env::var_os(HELPER_ENV).is_some() {
        run_helper();
        return;
    }

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("adopted_request_subprocess_zombies_are_reaped")
        .arg("--nocapture")
        .env(HELPER_ENV, "1")
        .status()
        .expect("spawn isolated subreaper test");
    assert!(status.success(), "isolated subreaper test failed");
}

fn run_helper() {
    let supervisor = LsphpSupervisor::new(SupervisorConfig::from_php_config(
        &PhpConfig::default(),
        "/tmp/hj-adopted-zombie-reap.sock",
        "",
        "",
    ));

    // This is the exact process shape used by PHP's `exec("curl ... &")`: the
    // shell exits first, curl is adopted by httpjet's subreaper, and curl exits
    // shortly afterward.
    let output = Command::new("/bin/sh")
        .args(["-c", "curl --version >/dev/null & echo $!"])
        .output()
        .expect("spawn detached request helper");
    assert!(output.status.success());
    let adopted_pid: u32 = String::from_utf8(output.stdout)
        .expect("pid output is utf8")
        .trim()
        .parse()
        .expect("pid output is numeric");

    for _ in 0..100 {
        if proc_state(adopted_pid) == Some(b'Z') {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        proc_state(adopted_pid),
        Some(b'Z'),
        "detached helper must become an adopted zombie before the monitor pass"
    );

    supervisor.poll_liveness();
    assert_eq!(
        proc_state(adopted_pid),
        None,
        "the monitor pass must reap the adopted request helper"
    );
}

fn proc_state(pid: u32) -> Option<u8> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(')')?.1.trim_start();
    tail.as_bytes().first().copied()
}
