use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn write_accepting_worker(tag: &str, ignore_sigterm: bool) -> PathBuf {
    let path = std::env::temp_dir().join(format!("hj-{tag}-worker-{}.py", std::process::id()));
    let signal_setup = if ignore_sigterm {
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\nsignal.signal(signal.SIGUSR1, signal.SIG_IGN)"
    } else {
        ""
    };
    let source = format!(
        r#"#!/usr/bin/python3
import signal
import socket
import struct
import os

{signal_setup}
os.setsid()
listener = socket.socket(fileno=0)

while True:
    stream, _ = listener.accept()
    try:
        pid = os.getpid()
        stream.sendall(b"LS\x06\x00" + struct.pack("=I", 16) + b"\x00PID" + struct.pack("=i", pid))
        header = b""
        while len(header) < 8:
            chunk = stream.recv(8 - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) == 8:
            total = struct.unpack("=I", header[4:8])[0]
            remaining = total - 8
            while remaining:
                chunk = stream.recv(remaining)
                if not chunk:
                    break
                remaining -= len(chunk)
            body = str(pid).encode()
            response_header = struct.pack("=ii", 0, 200)
            stream.sendall(b"LS\x03\x00" + struct.pack("=I", 8 + len(response_header)) + response_header)
            stream.sendall(b"LS\x04\x00" + struct.pack("=I", 8 + len(body)) + body)
            stream.sendall(b"LS\x05\x00" + struct.pack("=I", 8))
    finally:
        stream.close()
"#
    );
    std::fs::write(&path, source).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}
