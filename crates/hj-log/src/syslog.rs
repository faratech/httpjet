//! (Tier 2) Syslog access-log sink: the rendered access lines also go out as
//! RFC 5424 (or legacy RFC 3164) syslog datagrams — UDP, or a local unix dgram
//! socket such as `/dev/log` / `/run/systemd/journal/syslog`.
//!
//! The tap lives on the access writer task (see [`crate::writer::run`]): the
//! request path is untouched, and each line the writer already rendered is
//! framed once and sent best-effort. A failed or missing syslog receiver is
//! counted (`send_failures`) and never disturbs file logging.
//!
//! `MSG` is the rendered access line itself (Combined or JSON per the access
//! format), so any existing parser/alerting on the file lines keeps working on
//! the syslog feed. CR/LF/NUL in `MSG` are replaced with spaces: line-framed
//! transports treat LF as a record delimiter. Datagrams are capped at 1024
//! bytes by truncating `MSG` (never the header).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Maximum datagram size (header + SD + MSG). Deliberately under the classic
/// 1 KiB syslog line limit every legacy receiver accepts.
const MAX_DATAGRAM: usize = 1024;

/// Datagram destination for the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogTarget {
    Udp(SocketAddr),
    /// Local unix dgram socket (must exist and have a reader — `connect(2)`
    /// fails otherwise, which `SyslogTap::new` surfaces at startup).
    UnixDgram(PathBuf),
}

impl SyslogTarget {
    /// Parse `udp://host:port`, a bare `host:port` (UDP), or any value
    /// containing `/` as a unix dgram socket path.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(rest) = s.strip_prefix("udp://") {
            return rest.parse::<SocketAddr>().ok().map(SyslogTarget::Udp);
        }
        if s.contains('/') {
            return Some(SyslogTarget::UnixDgram(PathBuf::from(s)));
        }
        s.parse::<SocketAddr>().ok().map(SyslogTarget::Udp)
    }
}

/// RFC 5424 syslog facility (the PRI field's high bits: `PRI = facility*8 + severity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFacility {
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl SyslogFacility {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "user" => Self::User,
            "mail" => Self::Mail,
            "daemon" => Self::Daemon,
            "auth" => Self::Auth,
            "syslog" => Self::Syslog,
            "local0" => Self::Local0,
            "local1" => Self::Local1,
            "local2" => Self::Local2,
            "local3" => Self::Local3,
            "local4" => Self::Local4,
            "local5" => Self::Local5,
            "local6" => Self::Local6,
            "local7" => Self::Local7,
            _ => return None,
        })
    }

    fn pri_base(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

/// RFC 5424 severity (the PRI field's low three bits). Access records default
/// to `Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogSeverity {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl SyslogSeverity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "emerg" | "emergency" => Self::Emergency,
            "alert" => Self::Alert,
            "crit" | "critical" => Self::Critical,
            "err" | "error" => Self::Error,
            "warning" | "warn" => Self::Warning,
            "notice" => Self::Notice,
            "info" | "informational" => Self::Info,
            "debug" => Self::Debug,
            _ => return None,
        })
    }

    fn pri(self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

/// Sink configuration, read once at logger construction.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub target: SyslogTarget,
    pub facility: SyslogFacility,
    pub severity: SyslogSeverity,
    pub app_name: String,
    pub hostname: String,
    /// `true` (default) = RFC 5424; `false` = RFC 3164 BSD packet (no version,
    /// no structured data, ambiguous timestamp — kept for legacy receivers).
    pub rfc5424: bool,
}

/// A best-effort datagram sender bound to the configured target at construction.
type SyslogSend = Box<dyn Fn(&[u8]) -> std::io::Result<usize> + Send>;

/// Writer-side handle: owns the socket and frames one rendered access line per
/// datagram. `Clone` is deliberately NOT implemented — the tap is owned by the
/// single access writer task.
pub struct SyslogTap {
    cfg: SyslogConfig,
    send: SyslogSend,
    send_failures: AtomicU64,
}

impl SyslogTap {
    /// Build the socket and validate the destination. A unix dgram target that
    /// no process is reading fails here (at startup), not silently per line.
    pub fn new(cfg: SyslogConfig) -> std::io::Result<Self> {
        let send: SyslogSend = match &cfg.target {
            SyslogTarget::Udp(addr) => {
                let bind: std::net::SocketAddr = if addr.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let sock = std::net::UdpSocket::bind(bind)?;
                sock.set_nonblocking(true)?;
                let addr = *addr;
                Box::new(move |buf| sock.send_to(buf, addr))
            }
            SyslogTarget::UnixDgram(path) => {
                let sock = std::os::unix::net::UnixDatagram::unbound()?;
                sock.set_nonblocking(true)?;
                sock.connect(path)?;
                Box::new(move |buf| sock.send(buf))
            }
        };
        Ok(Self {
            cfg,
            send,
            send_failures: AtomicU64::new(0),
        })
    }

    /// Frame and send ONE rendered access line. Never panics; failures are
    /// counted (best-effort by contract) and never block the log writer.
    pub fn send_line(&self, line: &str) {
        if line.is_empty() {
            return;
        }
        let frame = render_frame(&self.cfg, SystemTime::now(), line);
        if self.send.as_ref()(&frame).is_err() {
            self.send_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Send a block of newline-terminated rendered lines (the writer's chunk
    /// path): split here so the request path never pays for it.
    pub fn send_chunk(&self, chunk: &[u8]) {
        for line in chunk.split(|&b| b == b'\n') {
            match std::str::from_utf8(line) {
                Ok(l) => self.send_line(l),
                Err(_) => {
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Datagrams that could not be handed to the syslog socket.
    pub fn send_failures(&self) -> u64 {
        self.send_failures.load(Ordering::Relaxed)
    }
}

/// Replace CR/LF/NUL with spaces so MSG stays one syslog record.
fn sanitize_msg(msg: &str) -> String {
    let needs = msg.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0);
    if !needs {
        return msg.to_owned();
    }
    msg.chars()
        .map(|c| match c {
            '\n' | '\r' | '\0' => ' ',
            c => c,
        })
        .collect()
}

/// Replace characters that would break the HEADER fields (spaces and controls
/// in PRINTASCII terms) so a hostile config value stays one token.
fn sanitize_token(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.:/@".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Render one syslog datagram. `MSG` = `msg` (an already-rendered access line).
///
/// RFC 5424: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG` with the
/// NILVALUE `-` for PROCID/MSGID (no structured data in v1). RFC 3164:
/// `<PRI>TIMESTAMP HOSTNAME APP-NAME: MSG`.
pub fn render_frame(cfg: &SyslogConfig, ts: SystemTime, msg: &str) -> Vec<u8> {
    let pri = cfg.facility.pri_base() * 8 + cfg.severity.pri();
    let host = sanitize_token(&cfg.hostname);
    let app = sanitize_token(&cfg.app_name);
    let msg = sanitize_msg(msg);

    let header = if cfg.rfc5424 {
        format!(
            "<{pri}>1 {} {host} {app} - - - ",
            crate::fmt::syslog_time(ts)
        )
    } else {
        format!("<{pri}>{} {host} {app}: ", crate::fmt::bsd_time(ts))
    };

    let budget = MAX_DATAGRAM.saturating_sub(header.len());
    let mut out = header.into_bytes();
    if msg.len() <= budget {
        out.extend_from_slice(msg.as_bytes());
    } else {
        // Truncate MSG at a char boundary; the header is never cut.
        let mut cut = budget;
        while cut > 0 && !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        out.extend_from_slice(msg[..cut].as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn cfg(target: SyslogTarget, rfc5424: bool) -> SyslogConfig {
        SyslogConfig {
            target,
            facility: SyslogFacility::Local0,
            severity: SyslogSeverity::Info,
            app_name: "httpjet".into(),
            hostname: "edge-1".into(),
            rfc5424,
        }
    }

    fn at(secs: u64, millis: u32) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(u64::from(millis))
    }

    #[test]
    fn target_parse_forms() {
        assert_eq!(
            SyslogTarget::parse("udp://127.0.0.1:514"),
            Some(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()))
        );
        assert_eq!(
            SyslogTarget::parse("10.0.0.9:514"),
            Some(SyslogTarget::Udp("10.0.0.9:514".parse().unwrap()))
        );
        assert_eq!(
            SyslogTarget::parse("/run/systemd/journal/syslog"),
            Some(SyslogTarget::UnixDgram(PathBuf::from(
                "/run/systemd/journal/syslog"
            )))
        );
        assert_eq!(SyslogTarget::parse(""), None);
    }

    #[test]
    fn pri_arithmetic() {
        // local0.info = 16*8 + 6 = 134; daemon.err = 3*8 + 3 = 27.
        assert_eq!(
            SyslogFacility::Local0.pri_base() * 8 + SyslogSeverity::Info.pri(),
            134
        );
        assert_eq!(
            SyslogFacility::Daemon.pri_base() * 8 + SyslogSeverity::Error.pri(),
            27
        );
        assert!(SyslogFacility::parse("local7").is_some());
        assert!(SyslogSeverity::parse("warning").is_some());
        assert!(SyslogSeverity::parse("bogus").is_none());
    }

    #[test]
    fn rfc5424_frame_shape() {
        let frame = render_frame(
            &cfg(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()), true),
            at(971_186_136, 42),
            "1.2.3.4 - - [x] \"GET / HTTP/1.1\" 200 5",
        );
        let text = String::from_utf8(frame).unwrap();
        assert!(
            text.starts_with("<134>1 2000-10-10T13:55:36.042Z edge-1 httpjet - - - "),
            "got {text}"
        );
        assert!(text.ends_with("\"GET / HTTP/1.1\" 200 5"));
    }

    #[test]
    fn rfc3164_frame_shape() {
        let frame = render_frame(
            &cfg(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()), false),
            at(971_186_136, 0),
            "hello",
        );
        let text = String::from_utf8(frame).unwrap();
        assert!(
            text.starts_with("<134>Oct 10 13:55:36 edge-1 httpjet: hello"),
            "got {text}"
        );
    }

    #[test]
    fn msg_control_chars_are_sanitized() {
        let frame = render_frame(
            &cfg(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()), true),
            at(0, 0),
            "a\nb\rc\0d",
        );
        let text = String::from_utf8(frame).unwrap();
        assert!(text.ends_with("a b c d"), "got {text}");
    }

    #[test]
    fn datagram_is_capped_by_truncating_msg_only() {
        let long = "x".repeat(4096);
        let frame = render_frame(
            &cfg(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()), true),
            at(0, 0),
            &long,
        );
        assert_eq!(frame.len(), MAX_DATAGRAM);
        // The header survived intact.
        assert!(frame.starts_with(b"<134>1 1970-01-01T00:00:00.000Z edge-1 httpjet - - - "));
    }

    #[test]
    fn hostile_header_tokens_stay_one_field() {
        let mut c = cfg(SyslogTarget::Udp("127.0.0.1:514".parse().unwrap()), true);
        c.hostname = "evil host\n.name".into();
        c.app_name = "app name".into();
        let frame = render_frame(&c, at(0, 0), "m");
        let text = String::from_utf8(frame).unwrap();
        assert!(
            text.starts_with("<134>1 1970-01-01T00:00:00.000Z evil-host-.name app-name - - - m"),
            "got {text}"
        );
    }

    #[test]
    fn udp_round_trip_delivers_the_frame() {
        // Bind a real loopback receiver and a tap pointed at it.
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = rx.local_addr().unwrap();
        let tap = SyslogTap::new(cfg(SyslogTarget::Udp(addr), true)).unwrap();
        tap.send_line("1.2.3.4 - - [x] \"GET /f HTTP/1.1\" 200 1");
        let mut buf = [0u8; 2048];
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("\"GET /f HTTP/1.1\" 200 1"), "got {text}");
        assert_eq!(tap.send_failures(), 0);
    }

    #[test]
    fn unix_dgram_without_receiver_fails_at_construction() {
        let dir = std::env::temp_dir().join(format!(
            "hj-syslog-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("no-socket-here");
        assert!(SyslogTap::new(cfg(SyslogTarget::UnixDgram(missing), true)).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chunk_splits_into_frames() {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = rx.local_addr().unwrap();
        let tap = SyslogTap::new(cfg(SyslogTarget::Udp(addr), true)).unwrap();
        tap.send_chunk(b"line-one\nline-two\n");
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut seen = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 2048];
            let (n, _) = rx.recv_from(&mut buf).unwrap();
            seen.push(String::from_utf8_lossy(&buf[..n]).to_string());
        }
        assert!(seen.iter().any(|s| s.ends_with("line-one")));
        assert!(seen.iter().any(|s| s.ends_with("line-two")));
    }
}
