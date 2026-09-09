//! Independent, opt-in read-only operational endpoint. Never used by the request pipeline.
use crate::state::ServerState;
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const ROWS: usize = 256;
const MAX_BODY: usize = 1024 * 1024;

pub fn parse_addr(value: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = value
        .parse()
        .map_err(|_| "expected a loopback socket address")?;
    if !addr.ip().is_loopback() {
        return Err("admin listener must bind loopback".into());
    }
    Ok(addr)
}

/// Version-local fingerprint of the normalized configuration, not certificate contents.
/// Stream Debug into a digest: do not create a plaintext copy of configuration secrets.
pub fn fingerprint(config: &hj_core::config::ServerConfig) -> String {
    struct Sink(Sha256);
    impl std::fmt::Write for Sink {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0.update(value.as_bytes());
            Ok(())
        }
    }
    let mut sink = Sink(Sha256::new());
    write!(&mut sink, "{config:?}").expect("digest writer cannot fail");
    format!("{:x}", sink.0.finalize())
}

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars().take(256) {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn snapshot(state: &ServerState) -> String {
    let listeners = state
        .server
        .listeners
        .iter()
        .take(ROWS)
        .map(|l| {
            format!(
                "{{\"name\":{},\"tls\":{},\"unix\":{}}}",
                quoted(&l.name),
                l.secure,
                l.uds_path.is_some()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let vhosts = state
        .server
        .vhosts
        .keys()
        .take(ROWS)
        .map(|s| quoted(s))
        .collect::<Vec<_>>()
        .join(",");
    let peers = state.proxy.pool().peer_snapshots();
    let upstreams = peers.iter().take(ROWS).map(|p| format!(
        "{{\"scope\":{},\"group\":{},\"peer\":{},\"healthy\":{},\"active\":{},\"selections\":{}}}",
        quoted(&p.scope), quoted(&p.group), p.peer, p.healthy, p.active, p.selections
    )).collect::<Vec<_>>().join(",");
    let cache = state
        .page_cache
        .as_ref()
        .map(|c| {
            let s = c.stats();
            format!(
                "{{\"entries\":{},\"memory_bytes\":{},\"hits\":{},\"misses\":{}}}",
                s.entries, s.memory_bytes, s.hits, s.misses
            )
        })
        .unwrap_or_else(|| "null".into());
    format!(
        "{{\"schema_version\":1,\"generation\":{},\"config_fingerprint\":{},\"truncated\":{},\"listeners\":[{}],\"vhosts\":[{}],\"upstreams\":[{}],\"page_cache\":{}}}",
        state.generation,
        quoted(&state.config_fingerprint),
        state.server.listeners.len() > ROWS
            || state.server.vhosts.len() > ROWS
            || peers.len() > ROWS,
        listeners,
        vhosts,
        upstreams,
        cache
    )
}

fn classify(buf: &[u8]) -> u16 {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(buf), Ok(httparse::Status::Complete(n)) if n == buf.len()) {
        return 400;
    }
    // No browser-origin access, upload framing, pipelining or mutable methods.
    if req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("origin")
            || h.name.eq_ignore_ascii_case("transfer-encoding")
            || h.name.eq_ignore_ascii_case("content-length")
    }) {
        return 400;
    }
    let hosts: Vec<_> = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"))
        .collect();
    if hosts.len() != 1 {
        return 400;
    }
    let host = std::str::from_utf8(hosts[0].value).unwrap_or("");
    if !host
        .parse::<SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback())
        && host != "localhost"
    {
        return 400;
    }
    if req.method != Some("GET") {
        return 405;
    }
    if req.path != Some("/v1/status") {
        return 404;
    }
    200
}

pub async fn serve(listener: TcpListener, holder: Arc<ArcSwap<ServerState>>) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept(), if tasks.len() < 4 => {
                let Ok((mut stream, peer)) = accepted else { break; };
                if !peer.ip().is_loopback() { continue; }
                let holder = holder.clone();
                tasks.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(5), async {
                        let mut buf = Vec::new();
                        let mut byte = [0];
                        while buf.len() < 4096 && !buf.ends_with(b"\r\n\r\n") {
                            if stream.read(&mut byte).await? == 0 { return Ok::<_, std::io::Error>(()); }
                            buf.push(byte[0]);
                        }
                        let mut status = classify(&buf);
                        let mut body = if status == 200 { snapshot(&holder.load_full()) } else { "{}".into() };
                        if body.len() > MAX_BODY { status = 503; body = "{}".into(); }
                        let head = format!("HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(head.as_bytes()).await?;
                        stream.write_all(body.as_bytes()).await?;
                        stream.shutdown().await
                    }).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bind_and_request_boundaries() {
        assert!(parse_addr("127.0.0.1:0").is_ok());
        assert!(parse_addr("0.0.0.0:9091").is_err());
        assert_eq!(
            classify(b"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1:9091\r\n\r\n"),
            200
        );
        for bad in [
            "Origin: https://evil.test\r\n",
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\n",
        ] {
            assert_eq!(
                classify(
                    format!("GET /v1/status HTTP/1.1\r\nHost: localhost\r\n{bad}\r\n").as_bytes()
                ),
                400
            );
        }
        assert_eq!(
            classify(b"POST /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            405
        );
        assert_eq!(quoted("a\n\"\\"), "\"a\\u000a\\\"\\\\\"");
    }
    #[test]
    fn fingerprints_are_repeatable_and_sensitive() {
        let mut c = hj_core::config::ServerConfig::default();
        assert_eq!(fingerprint(&c), fingerprint(&c));
        let before = fingerprint(&c);
        c.server_name = "changed".into();
        assert_ne!(before, fingerprint(&c));
    }
}
